// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// NAALP-MCP binding profile for the C# SDK (design.md §19; Companion-Spec Requirement 6.1) — a
    /// draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
    /// signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
    /// (<see cref="Envelope"/>) on the Bridge channel, and it REUSES the closed effect lattice
    /// (<see cref="Policy"/>), the approval + single-use consume ledger (<see cref="Approval"/>), and the
    /// T1 content-id framing (§2.3) UNCHANGED.
    ///
    /// <para>What the profile adds is the governance MCP itself lacks. The MCP specification states
    /// plainly that a tool's annotations are unenforced hints a malicious server can lie about — "clients
    /// MUST consider tool annotations to be untrusted unless they come from trusted servers". This
    /// profile turns that anonymous, untrusted hint into a SIGNED effect claim by a named key:</para>
    ///
    /// <list type="bullet">
    /// <item>CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are
    /// carried OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization
    /// identity — the wrapping signer is the authority (R-14.6).</item>
    /// <item>PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice.
    /// Because the spine carries no CBOR boolean (design §3.1), each JSON hint is transcribed as the uint
    /// 1/0; an ABSENT hint takes its MCP default. destructiveHint's default of TRUE is why an
    /// un-annotated write maps to destructive — the fail-closed rule.</item>
    /// <item>THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
    /// DECLARED effect, under its ML-DSA signature. A verifier independently recomputes the
    /// annotation-derived effect and enforces the MORE SEVERE of the two (the good-regulator attenuator:
    /// a disagreeing input collapses UP, never down). A signer that DECLARES BELOW its own carried
    /// annotations is rejected fail-closed (EffectUnderDeclared); an annotation set mapping outside the
    /// lattice is rejected (MalformedAnnotation), never defaulted to benign.</item>
    /// <item>THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
    /// (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
    /// invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.</item>
    /// </list>
    ///
    /// <para>Every check is fail-closed (§15). Ported from impl/go/mcp; the byte surface (annotation
    /// encoding, the mapping table, tool-call bodies/content-ids, call bindings, resolution verdicts) is
    /// graded against vectors/mcp/cases.json; the signed governance path (VerifyToolCall / AuthorizeCall)
    /// uses real deterministic ML-DSA-65 and is demonstrated in isolation only (the corpus carries no
    /// signed vector).</para>
    /// </summary>
    public static class Mcp
    {
        // Channel binding, the tier-1 kind code, and the tier. McpToolCall is kind 1 on the Bridge
        // channel — a named escalation over the frozen baseline Carriage kind (0), which stays untouched.
        public const long ChannelBridge = 0x000D;   // Bridge channel (foreign carriage lives here)
        public const long KindMcpToolCall = 1;       // tier-1 kind code (baseline Carriage is kind 0)
        public const long Tier = 1;                  // a named escalation adding the governed MCP wrapper

        // Annotation CBOR keys inside a naalp-mcp-annotations map. Each value is the uint 1 (true) / 0
        // (false) — the spine carries no CBOR boolean (design §3.1).
        public const long KeyReadOnly = 1;    // MCP readOnlyHint
        public const long KeyDestructive = 2; // MCP destructiveHint
        public const long KeyIdempotent = 3;  // MCP idempotentHint
        public const long KeyOpenWorld = 4;   // MCP openWorldHint (ADVISORY — not an effect determinant)

        // MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an
        // un-annotated write maps to destructive — the fail-closed default.
        public const bool DefaultReadOnly = false;
        public const bool DefaultDestructive = true;
        public const bool DefaultIdempotent = false;

        // contentID is the T1 content-id framing over arbitrary bytes: multihash(0x20, SHA-384(b)).
        private static byte[] ContentIdOf(byte[] b) => Cbor.ContentId(b);

        // ---- the transcribed MCP annotation set (naalp-mcp-annotations) ---------------------------

        /// <summary>The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is
        /// OPTIONAL: null means the hint was absent (the MCP default applies in the mapping), so an
        /// absent hint and a present false are distinct on the wire though they may resolve to the same
        /// effect. OpenWorld is carried for accountability but never enters the effect mapping.</summary>
        public sealed class Annotations
        {
            public readonly bool? ReadOnly;    // MCP readOnlyHint
            public readonly bool? Destructive; // MCP destructiveHint
            public readonly bool? Idempotent;  // MCP idempotentHint
            public readonly bool? OpenWorld;   // MCP openWorldHint (advisory only)

            public Annotations(bool? readOnly = null, bool? destructive = null, bool? idempotent = null, bool? openWorld = null)
            {
                ReadOnly = readOnly;
                Destructive = destructive;
                Idempotent = idempotent;
                OpenWorld = openWorld;
            }

            private static Cbor.U U01(bool b) => new Cbor.U(b ? 1 : 0);

            /// <summary>Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1.</summary>
            public Cbor.Value ToValue()
            {
                var pairs = new List<Cbor.Pair>();
                if (ReadOnly != null) pairs.Add(new Cbor.Pair(new Cbor.U(KeyReadOnly), U01(ReadOnly.Value)));
                if (Destructive != null) pairs.Add(new Cbor.Pair(new Cbor.U(KeyDestructive), U01(Destructive.Value)));
                if (Idempotent != null) pairs.Add(new Cbor.Pair(new Cbor.U(KeyIdempotent), U01(Idempotent.Value)));
                if (OpenWorld != null) pairs.Add(new Cbor.Pair(new Cbor.U(KeyOpenWorld), U01(OpenWorld.Value)));
                return new Cbor.M(pairs);
            }

            /// <summary>The deterministic-CBOR bytes of the annotation map (keys sorted by Encode).</summary>
            public byte[] Encode() => Cbor.Encode(ToValue());
        }

        /// <summary>Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a
        /// non-map, a non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no
        /// boolean), a duplicate key, or an annotation key outside the closed mapping {1,2,3,4}. Such a
        /// set would map outside the closed lattice, so it is rejected, never defaulted to benign.</summary>
        public static Annotations AnnotationsFromValue(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("MalformedAnnotation", "annotation set is not a map");
            }
            bool? ro = null, de = null, idem = null, ow = null;
            var seen = new HashSet<long>();
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("MalformedAnnotation", "non-uint annotation key");
                }
                if (!(p.Val is Cbor.U uv) || uv.V > 1) // a hint value outside {0,1} maps outside the lattice
                {
                    throw new NaalpException("MalformedAnnotation", "annotation hint value is outside {0,1}");
                }
                if (!seen.Add(ku.V))
                {
                    throw new NaalpException("MalformedAnnotation", "duplicate annotation key");
                }
                bool flag = uv.V == 1;
                switch (ku.V)
                {
                    case KeyReadOnly: ro = flag; break;
                    case KeyDestructive: de = flag; break;
                    case KeyIdempotent: idem = flag; break;
                    case KeyOpenWorld: ow = flag; break;
                    default:
                        throw new NaalpException("MalformedAnnotation", "annotation key outside the closed mapping");
                }
            }
            return new Annotations(ro, de, idem, ow);
        }

        // ---- the published annotation -> effect mapping table (design §6.1) -----------------------

        /// <summary>Map a tool's transcribed annotations to the closed four-effect lattice by the
        /// published table, applying the MCP default for each absent hint:
        /// readOnlyHint true -> read_only; readOnlyHint false + destructiveHint true -> destructive;
        /// readOnlyHint false + destructiveHint false + idem true -> idempotent_write; else
        /// non_idempotent_write. An absent destructiveHint defaults TRUE, so a tool with no annotations
        /// maps to destructive — the fail-closed collapse. openWorldHint is never consulted (design §5).</summary>
        public static long MapAnnotationsToEffect(Annotations a)
        {
            bool ro = a.ReadOnly ?? DefaultReadOnly;
            bool de = a.Destructive ?? DefaultDestructive;
            bool idem = a.Idempotent ?? DefaultIdempotent;
            if (ro)
            {
                return Policy.READ_ONLY;
            }
            if (de)
            {
                return Policy.DESTRUCTIVE;
            }
            if (idem)
            {
                return Policy.IDEMPOTENT_WRITE;
            }
            return Policy.NON_IDEMPOTENT_WRITE;
        }

        /// <summary>The more-severe resolution (the good-regulator attenuator). Given the
        /// annotation-derived effect and the wrapping signer's declared effect, return
        /// (enforced, mismatch) — the enforced effect being the MORE SEVERE (equal to declared on
        /// success), and mismatch whether the two disagreed (attributable to the wrapping signer). A
        /// declared value outside the closed lattice is EffectOutsideLattice; a declared value BELOW the
        /// annotation-derived effect is EffectUnderDeclared (a wrapper's declared effect can never sit
        /// under its own carried annotations' mapping).</summary>
        public static (long Enforced, bool Mismatch) ResolveEnforcedEffect(long annotationMapped, long declared)
        {
            if (declared > Policy.DESTRUCTIVE)
            {
                throw new NaalpException("EffectOutsideLattice", "declared effect outside the closed four-effect lattice");
            }
            if (declared < annotationMapped)
            {
                throw new NaalpException("EffectUnderDeclared", "declared effect is below the annotation-mapped effect");
            }
            return (declared, declared != annotationMapped);
        }

        // ---- the wrapper body (naalp-mcp-tool-call) -----------------------------------------------

        /// <summary>The wrapper body (envelope field 10). Tool and Args are the foreign MCP bytes,
        /// carried octet-for-octet (carriage, not adoption); Annotations is the wrapping signer's
        /// transcription of the tool's hints, on which the mapping operates. The wrapper's OWN effect is
        /// envelope field 7, not a body field.</summary>
        public sealed class ToolCall
        {
            public readonly byte[] Tool;
            public readonly byte[] Args;
            public readonly Annotations Annotations;

            public ToolCall(byte[] tool, byte[] args, Annotations annotations)
            {
                Tool = (byte[])tool.Clone();
                Args = (byte[])args.Clone();
                Annotations = annotations;
            }

            internal Cbor.M ToMap()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Tool)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Args)),
                    new Cbor.Pair(new Cbor.U(3), Annotations.ToValue()),
                });
            }

            /// <summary>Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToMap());

            /// <summary>The tool-call body's content id (T1 framing).</summary>
            public byte[] ContentId() => ContentIdOf(Bytes());

            /// <summary>The (tool_id, args_id) binding whose content id an approval binds for this call.</summary>
            public CallBinding CallBinding() => NewCallBinding(Tool, Args);

            /// <summary>Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1,
            /// Bridge channel, kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the
            /// tool-call body as field 10, and causes. The caller signs it; the signer BECOMES
            /// accountable for the declared effect and the annotation transcription. A declared effect
            /// outside the closed lattice is rejected fail-closed. Under-declaration is NOT rejected here
            /// — it is a signed, attributable claim whose inconsistency VerifyToolCall surfaces as
            /// EffectUnderDeclared at the enforcement point.</summary>
            public Envelope.Object EnvelopeObject(byte[] signer, long created, long profile, long declared, List<byte[]> causes)
            {
                if (declared > Policy.DESTRUCTIVE)
                {
                    throw new NaalpException("EffectOutsideLattice", "declared effect outside the closed lattice");
                }
                return new Envelope.Object(
                    kind: KindMcpToolCall, channel: ChannelBridge, signer: signer, created: created,
                    effect: declared, body: ToMap(), tier: Tier, profile: profile, causes: causes);
            }
        }

        /// <summary>Parse an envelope object body (a decoded cbor Value) into a ToolCall. A body that is
        /// not exactly {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is
        /// ToolCallMalformed; a malformed annotation set is MalformedAnnotation. Fail-closed.</summary>
        public static ToolCall ToolCallFromBody(Cbor.Value v)
        {
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("ToolCallMalformed", "tool-call body is not a map");
            }
            byte[]? tool = null, args = null;
            Annotations? ann = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("ToolCallMalformed", "non-uint tool-call body key");
                }
                switch (ku.V)
                {
                    case 1:
                        if (!(p.Val is Cbor.B tb)) throw new NaalpException("ToolCallMalformed", "tool is not a bstr");
                        tool = tb.V;
                        break;
                    case 2:
                        if (!(p.Val is Cbor.B ab)) throw new NaalpException("ToolCallMalformed", "args is not a bstr");
                        args = ab.V;
                        break;
                    case 3:
                        ann = AnnotationsFromValue(p.Val); // throws MalformedAnnotation
                        break;
                    default:
                        throw new NaalpException("ToolCallMalformed", "unknown tool-call body field");
                }
            }
            if (tool == null || args == null || ann == null)
            {
                throw new NaalpException("ToolCallMalformed", "tool-call body missing a mandatory field");
            }
            return new ToolCall(tool, args, ann);
        }

        // ---- the call binding an approval binds (naalp-mcp-call-binding) --------------------------

        /// <summary>Names the exact tool call by content id: the tool bytes' content id AND the args
        /// bytes' content id. An approval binds the content id of THIS binding, so a changed tool
        /// description (new ToolId) OR changed arguments (new ArgsId) yields a new call content id and
        /// invalidates a prior approval bound to the old one (Requirement 6.1).</summary>
        public sealed class CallBinding
        {
            public readonly byte[] ToolId; // multihash(0x20, SHA-384(tool bytes))
            public readonly byte[] ArgsId; // multihash(0x20, SHA-384(args bytes))

            public CallBinding(byte[] toolId, byte[] argsId)
            {
                ToolId = (byte[])toolId.Clone();
                ArgsId = (byte[])argsId.Clone();
            }

            internal Cbor.M ToMap()
            {
                return new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(ToolId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(ArgsId)),
                });
            }

            /// <summary>Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.</summary>
            public byte[] Bytes() => Cbor.Encode(ToMap());

            /// <summary>The call content id an approval binds.</summary>
            public byte[] ContentId() => ContentIdOf(Bytes());
        }

        /// <summary>Compute the binding from the raw tool and args bytes.</summary>
        public static CallBinding NewCallBinding(byte[] tool, byte[] args)
        {
            return new CallBinding(ContentIdOf(tool), ContentIdOf(args));
        }

        // ---- kind validation (composes with the frozen baseline) ----------------------------------

        /// <summary>Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).</summary>
        public static bool KindValidator(long channel, long kind)
        {
            return channel == ChannelBridge && kind == KindMcpToolCall;
        }

        private static bool BaselineKind(long channel, long kind)
        {
            try
            {
                Channels.Lookup(channel, kind);
                return true;
            }
            catch (NaalpException)
            {
                return false;
            }
        }

        /// <summary>Accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator an
        /// MCP-aware endpoint passes to Envelope.Verify. A baseline-only endpoint using the baseline
        /// validator alone correctly rejects an McpToolCall as UnknownKind (fail-closed).</summary>
        public static bool ComposedKindValidator(long channel, long kind)
        {
            return BaselineKind(channel, kind) || KindValidator(channel, kind);
        }

        // ---- verified tool call -------------------------------------------------------------------

        /// <summary>An MCP tool call that has passed envelope verification and effect resolution. It
        /// carries the enforced effect (the more-severe value C5 authorizes on), whether the annotation
        /// and declared effect disagreed (Mismatch — attributable to Signer), and the parsed tool
        /// call.</summary>
        public sealed class Resolved
        {
            public readonly byte[] ContentId;
            public readonly byte[] Signer;
            public readonly ToolCall ToolCall;
            public readonly long AnnotationMapped;
            public readonly long Declared;
            public readonly long Enforced;
            public readonly bool Mismatch;

            public Resolved(byte[] contentId, byte[] signer, ToolCall toolCall,
                long annotationMapped, long declared, long enforced, bool mismatch)
            {
                ContentId = contentId;
                Signer = signer;
                ToolCall = toolCall;
                AnnotationMapped = annotationMapped;
                Declared = declared;
                Enforced = enforced;
                Mismatch = mismatch;
            }
        }

        /// <summary>Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1)
        /// verifies the signed object with real crypto (Envelope.Verify against the composed validator —
        /// content id, ranges, header/body, kind dispatch, signature); (2) confirms it is a tier-1
        /// Bridge McpToolCall; (3) parses the tool-call body (rejecting a malformed annotation set);
        /// (4) recomputes the annotation-derived effect from the CARRIED annotations, independent of the
        /// declared effect; (5) resolves the enforced effect to the MORE SEVERE, rejecting
        /// under-declaration. The enforced effect equals the declared envelope effect on success, so the
        /// object's field 7 is the correct C5 authorization input. Any failure throws its named error
        /// and authorizes nothing (fail-closed).</summary>
        public static Resolved VerifyToolCall(int profile, int alg, byte[] pubkey, byte[] signedObj)
        {
            Envelope.Object o = Envelope.Verify(profile, alg, pubkey, ComposedKindValidator, signedObj);
            if (o.Channel != ChannelBridge || o.Kind != KindMcpToolCall || o.Tier != Tier)
            {
                throw new NaalpException("ToolCallMalformed", "not a tier-1 Bridge McpToolCall");
            }
            ToolCall tc = ToolCallFromBody(o.Body);
            long mapped = MapAnnotationsToEffect(tc.Annotations);
            long declared = o.Effect; // Envelope.Verify already range-checked field 7 to 0..3
            (long enforced, bool mismatch) = ResolveEnforcedEffect(mapped, declared);
            return new Resolved(o.Id!, o.Signer, tc, mapped, declared, enforced, mismatch);
        }

        // ---- the per-call approval gate (reuses §7 approval + consume ledger) ---------------------

        /// <summary>Enforce the profile's per-call approval gate for a verified tool call. The approval
        /// MUST bind the EXACT call binding content id (tool_id + args_id) — so it satisfies neither a
        /// call with different arguments nor a call whose tool description changed (Requirement 6.1) —
        /// its granted effect must cover the call's ENFORCED (more-severe) effect, it must be unexpired
        /// at <paramref name="now"/>, and it is consumed single-use by <paramref name="by"/> through the
        /// §7 ledger. Precedence and fail-closed behaviour mirror the spine: a non-matching or
        /// under-granting approval denies ApprovalRequired with no ledger append; an already-spent
        /// approval denies AlreadyConsumed; the consume (the single state change) happens only when every
        /// check holds.</summary>
        public static void AuthorizeCall(Resolved r, Approval.ApprovalRecord appr, int approverAlg,
            byte[] approverPubkey, byte[] apprSig, string by, long now, Approval.Ledger ledger)
        {
            byte[] callCid = r.ToolCall.CallBinding().ContentId();
            try
            {
                Approval.VerifyApproval(appr, approverAlg, approverPubkey, apprSig, callCid, now);
            }
            catch (NaalpException e) when (e.Kind == "ApprovalMismatch")
            {
                // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
                throw new NaalpException("ApprovalRequired", "approval does not bind this exact call");
            }
            if (!Policy.Authorizes(appr.Grant, r.Enforced))
            {
                throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover the call");
            }
            ledger.Consume(appr.Id(), by); // AlreadyConsumed on replay (fail-closed, no double-spend)
        }
    }
}
