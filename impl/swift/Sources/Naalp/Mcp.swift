// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// NAALP-MCP binding profile for the Swift SDK (design.md §19; Companion-Spec Requirement 6.1) — a
// draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
// signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
// (envelope §2) on the Bridge channel, and it REUSES the closed effect lattice (Policy), the approval
// + single-use consume ledger (Approval), and the T1 content-id framing (§2.3) UNCHANGED.
//
// What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that
// a tool's annotations are unenforced hints a malicious server can lie about — "clients MUST consider
// tool annotations to be untrusted unless they come from trusted servers". This profile turns that
// anonymous, untrusted hint into a SIGNED effect claim by a named key:
//
//   - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are
//     carried OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization
//     identity — the wrapping signer is the authority (R-14.6).
//   - PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice. Because
//     the spine carries no CBOR boolean (design §3.1), each JSON hint is transcribed as the uint 1/0;
//     an ABSENT hint takes its MCP default. destructiveHint's default of TRUE is why an un-annotated
//     write maps to destructive — the fail-closed rule.
//   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
//     DECLARED effect. A verifier independently recomputes the annotation-derived effect and enforces
//     the MORE SEVERE of the two (resolveEnforcedEffect — the good-regulator attenuator: a disagreeing
//     input collapses UP, never down). A signer that DECLARES BELOW its own carried annotations is
//     rejected fail-closed (EffectUnderDeclared); an annotation set mapping outside the lattice is
//     rejected (MalformedAnnotation), never defaulted to benign.
//   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
//     (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
//     invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
//
// An independent transcription of impl/go/mcp (cross-read against impl/python/naalp/mcp.py), graded
// against the shared vectors/mcp/cases.json. The byte surface (annotation encoding, the mapping table,
// tool-call bodies/content-ids, call bindings, the resolution verdicts) is pure and signature-
// independent — the corpus grades byte-identical output.
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces above are pure. Swift cannot deterministically
// sign or verify ML-DSA (FIPS 204) with SwiftDilithium 3.6.0, so the per-call §7 approval gate
// (authorizeCall) takes an injected `(msg, sig) -> Bool` verifier (Ed25519 on this pure port), reusing
// the Approval single-use consume ledger UNCHANGED to demonstrate the consume loop in isolation.
// verifyToolCall is the full faithful transcription over Envelope.verify; on the pure port a level-0
// Ed25519 McpToolCall object is below the profile floor, so its reachable branch is ProfileDowngrade
// (its success path needs an ML-DSA level-3 signature the pure tier cannot produce — honest F2/F4,
// mirroring the PHP/C# ports). The reference's ML-DSA cross-language signed pins are NOT reproducible
// here and are NOT fabricated.
//
// Every check is fail-closed (§15): an object failing any check is rejected whole, returns its named
// error, and causes no state change.

import Crypto
import Foundation

public enum Mcp {

    /// Channel binding, the tier-1 kind code, and the tier. McpToolCall is kind 1 on the Bridge channel
    /// — a named escalation over the frozen baseline Carriage kind (0), which stays untouched (R-15A.2).
    public static let CHANNEL_BRIDGE: UInt64 = 0x000D  // Bridge channel (foreign carriage lives here)
    public static let KIND_MCP_TOOL_CALL: UInt64 = 1   // tier-1 kind code (baseline Carriage is kind 0)
    public static let TIER: UInt64 = 1                 // a named escalation adding the governed MCP wrapper

    /// Annotation CBOR keys inside a naalp-mcp-annotations map. Each value is the uint 1 (true) / 0
    /// (false) — the spine carries no CBOR boolean (design §3.1).
    public static let KEY_READ_ONLY: UInt64 = 1        // MCP readOnlyHint
    public static let KEY_DESTRUCTIVE: UInt64 = 2      // MCP destructiveHint
    public static let KEY_IDEMPOTENT: UInt64 = 3       // MCP idempotentHint
    public static let KEY_OPEN_WORLD: UInt64 = 4       // MCP openWorldHint (ADVISORY — not an effect determinant)

    /// MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
    /// write maps to destructive — the fail-closed default.
    public static let DEFAULT_READ_ONLY = false
    public static let DEFAULT_DESTRUCTIVE = true
    public static let DEFAULT_IDEMPOTENT = false

    // ---- the transcribed MCP annotation set (naalp-mcp-annotations) -------------------------------

    /// The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL: nil
    /// means the hint was absent (the MCP default applies in the mapping), so an absent hint and a
    /// present false are distinct on the wire though they may resolve to the same effect. openWorld is
    /// carried for accountability but never enters the effect mapping (design §5).
    public struct Annotations {
        public let readOnly: Bool?     // MCP readOnlyHint
        public let destructive: Bool?  // MCP destructiveHint
        public let idempotent: Bool?   // MCP idempotentHint
        public let openWorld: Bool?    // MCP openWorldHint (advisory only)

        public init(readOnly: Bool? = nil, destructive: Bool? = nil, idempotent: Bool? = nil, openWorld: Bool? = nil) {
            self.readOnly = readOnly
            self.destructive = destructive
            self.idempotent = idempotent
            self.openWorld = openWorld
        }

        private static func u01(_ b: Bool) -> CborValue { .u(b ? 1 : 0) }

        /// Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1.
        public func toValue() -> CborValue {
            var pairs: [(CborValue, CborValue)] = []
            if let ro = readOnly { pairs.append((.u(KEY_READ_ONLY), Self.u01(ro))) }
            if let de = destructive { pairs.append((.u(KEY_DESTRUCTIVE), Self.u01(de))) }
            if let idem = idempotent { pairs.append((.u(KEY_IDEMPOTENT), Self.u01(idem))) }
            if let ow = openWorld { pairs.append((.u(KEY_OPEN_WORLD), Self.u01(ow))) }
            return .m(pairs)
        }

        /// The deterministic-CBOR bytes of the annotation map (keys sorted by encode).
        public func encode() throws -> [UInt8] {
            return try Cbor.encode(toValue())
        }
    }

    /// Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a
    /// non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a
    /// duplicate key, or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map
    /// outside the closed lattice, so it is rejected, never defaulted to benign (AC-6.1.2).
    public static func annotationsFromValue(_ v: CborValue) throws -> Annotations {
        guard case let .m(pairs) = v else {
            throw NaalpError("MalformedAnnotation", "annotation set is not a map")
        }
        var ro: Bool? = nil, de: Bool? = nil, idem: Bool? = nil, ow: Bool? = nil
        var seen = Set<UInt64>()
        for (k, val) in pairs {
            guard case let .u(key) = k else {
                throw NaalpError("MalformedAnnotation", "non-uint annotation key")
            }
            guard case let .u(u) = val, u <= 1 else {  // a hint value outside {0,1} maps outside the lattice
                throw NaalpError("MalformedAnnotation", "annotation hint value is outside {0,1}")
            }
            if seen.contains(key) {
                throw NaalpError("MalformedAnnotation", "duplicate annotation key")
            }
            seen.insert(key)
            let flag = u == 1
            switch key {
            case KEY_READ_ONLY: ro = flag
            case KEY_DESTRUCTIVE: de = flag
            case KEY_IDEMPOTENT: idem = flag
            case KEY_OPEN_WORLD: ow = flag
            default:
                throw NaalpError("MalformedAnnotation", "annotation key outside the closed mapping")
            }
        }
        return Annotations(readOnly: ro, destructive: de, idempotent: idem, openWorld: ow)
    }

    // ---- the published annotation -> effect mapping table (design §6.1) ---------------------------

    /// Map a tool's transcribed annotations to the closed four-effect lattice by the published table,
    /// applying the MCP default for each absent hint:
    ///
    ///   readOnlyHint true                                  -> read_only
    ///   readOnlyHint false, destructiveHint true           -> destructive
    ///   readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
    ///   readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write
    ///
    /// An absent destructiveHint defaults TRUE, so a tool with no annotations maps to destructive — the
    /// fail-closed collapse to the most-severe. openWorldHint is never consulted (design §5).
    public static func mapAnnotationsToEffect(_ a: Annotations) -> Int {
        let ro = a.readOnly ?? DEFAULT_READ_ONLY
        let de = a.destructive ?? DEFAULT_DESTRUCTIVE
        let idem = a.idempotent ?? DEFAULT_IDEMPOTENT
        if ro { return Policy.READ_ONLY }
        if de { return Policy.DESTRUCTIVE }
        if idem { return Policy.IDEMPOTENT_WRITE }
        return Policy.NON_IDEMPOTENT_WRITE
    }

    /// The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect
    /// and the wrapping signer's declared effect, return (enforced, mismatch) — the enforced effect
    /// being the MORE SEVERE (equal to `declared` on success), and mismatch whether the two disagreed
    /// (attributable to the wrapping signer). A declared value outside the closed lattice is
    /// EffectOutsideLattice; a declared value BELOW the annotation-derived effect is EffectUnderDeclared
    /// (a wrapper's declared effect can never sit under its own carried annotations' mapping).
    public static func resolveEnforcedEffect(_ annotationMapped: Int, _ declared: Int) throws -> (enforced: Int, mismatch: Bool) {
        if declared > Policy.DESTRUCTIVE {
            throw NaalpError("EffectOutsideLattice", "declared effect outside the closed four-effect lattice")
        }
        if declared < annotationMapped {
            throw NaalpError("EffectUnderDeclared", "declared effect is below the annotation-mapped effect")
        }
        return (declared, declared != annotationMapped)
    }

    // ---- the wrapper body (naalp-mcp-tool-call) ---------------------------------------------------

    /// The wrapper body (envelope field 10). `tool` and `args` are the foreign MCP bytes, carried
    /// octet-for-octet (carriage, not adoption); `annotations` is the wrapping signer's transcription of
    /// the tool's hints, on which the mapping operates. The wrapper's OWN effect is envelope field 7,
    /// not a body field.
    public struct ToolCall {
        public let tool: [UInt8]
        public let args: [UInt8]
        public let annotations: Annotations

        public init(_ tool: [UInt8], _ args: [UInt8], _ annotations: Annotations) {
            self.tool = tool
            self.args = args
            self.annotations = annotations
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .b(tool)),
                (.u(2), .b(args)),
                (.u(3), annotations.toValue()),
            ])
        }

        /// Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(toMap())
        }

        /// The tool-call body's content id (T1 framing): multihash(0x20, SHA-384(body)).
        public func contentId() throws -> [UInt8] {
            return Cbor.contentId(try bytes())
        }

        /// The (tool_id, args_id) binding whose content id an approval binds for this call.
        public func callBinding() -> CallBinding {
            return Mcp.newCallBinding(tool, args)
        }

        /// Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel,
        /// kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as
        /// field 10, and `causes`. The caller signs it; the signer BECOMES accountable for the declared
        /// effect and the annotation transcription. A declared effect outside the closed lattice is
        /// rejected fail-closed. Under-declaration is NOT rejected here — it is a signed, attributable
        /// claim whose inconsistency verifyToolCall surfaces as EffectUnderDeclared at enforcement.
        public func envelopeObject(signer: [UInt8], created: UInt64, profile: UInt64, declared: Int, causes: [[UInt8]]) throws -> Envelope.Object {
            if declared > Policy.DESTRUCTIVE {
                throw NaalpError("EffectOutsideLattice", "declared effect outside the closed lattice")
            }
            return Envelope.Object(
                kind: KIND_MCP_TOOL_CALL, channel: CHANNEL_BRIDGE, signer: signer, created: created,
                effect: UInt64(declared), body: toMap(), tier: TIER, profile: profile, causes: causes)
        }
    }

    /// Parse an envelope object body (a decoded cbor value) into a ToolCall. A body that is not exactly
    /// {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a
    /// malformed annotation set is MalformedAnnotation. Fail-closed.
    public static func toolCallFromBody(_ v: CborValue) throws -> ToolCall {
        guard case let .m(pairs) = v else {
            throw NaalpError("ToolCallMalformed", "tool-call body is not a map")
        }
        var tool: [UInt8]? = nil, args: [UInt8]? = nil, ann: Annotations? = nil
        for (k, val) in pairs {
            guard case let .u(key) = k else {
                throw NaalpError("ToolCallMalformed", "non-uint tool-call body key")
            }
            switch key {
            case 1:
                guard case let .b(b) = val else { throw NaalpError("ToolCallMalformed", "tool is not a bstr") }
                tool = b
            case 2:
                guard case let .b(b) = val else { throw NaalpError("ToolCallMalformed", "args is not a bstr") }
                args = b
            case 3:
                ann = try annotationsFromValue(val)  // throws MalformedAnnotation
            default:
                throw NaalpError("ToolCallMalformed", "unknown tool-call body field \(key)")
            }
        }
        guard let t = tool, let a = args, let an = ann else {
            throw NaalpError("ToolCallMalformed", "tool-call body missing a mandatory field")
        }
        return ToolCall(t, a, an)
    }

    // ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

    /// Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content
    /// id. An approval binds the content id of THIS binding, so a changed tool description (new toolID)
    /// OR changed arguments (new argsID) yields a new call content id and invalidates a prior approval
    /// bound to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
    public struct CallBinding {
        public let toolID: [UInt8]  // multihash(0x20, SHA-384(tool bytes))
        public let argsID: [UInt8]  // multihash(0x20, SHA-384(args bytes))

        public init(toolID: [UInt8], argsID: [UInt8]) {
            self.toolID = toolID
            self.argsID = argsID
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .b(toolID)),
                (.u(2), .b(argsID)),
            ])
        }

        /// Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(toMap())
        }

        /// The call content id an approval binds.
        public func contentId() throws -> [UInt8] {
            return Cbor.contentId(try bytes())
        }
    }

    /// Compute the binding from the raw tool and args bytes.
    public static func newCallBinding(_ tool: [UInt8], _ args: [UInt8]) -> CallBinding {
        return CallBinding(toolID: Cbor.contentId(tool), argsID: Cbor.contentId(args))
    }

    // ---- kind validation (composes with the frozen baseline) --------------------------------------

    /// Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).
    public static func kindValidator(_ channel: UInt64, _ kind: UInt64) -> Bool {
        return channel == CHANNEL_BRIDGE && kind == KIND_MCP_TOOL_CALL
    }

    /// Accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator an MCP-aware endpoint
    /// passes to Envelope.verify. A baseline-only endpoint using the baseline validator alone correctly
    /// rejects an McpToolCall as UnknownKind (fail-closed).
    public static func composedKindValidator(_ channel: UInt64, _ kind: UInt64) -> Bool {
        if (try? Channels.lookup(Int(channel), Int(kind))) != nil {
            return true
        }
        return kindValidator(channel, kind)
    }

    // ---- verified tool call -----------------------------------------------------------------------

    /// An MCP tool call that has passed envelope verification and effect resolution. It carries the
    /// enforced effect (the more-severe value C5 authorizes on), whether the annotation and declared
    /// effect disagreed (mismatch — attributable to signer), and the parsed tool call.
    public struct Resolved {
        public let contentID: [UInt8]
        public let signer: [UInt8]
        public let toolCall: ToolCall
        public let annotationMapped: Int
        public let declared: Int
        public let enforced: Int
        public let mismatch: Bool

        public init(contentID: [UInt8], signer: [UInt8], toolCall: ToolCall,
                    annotationMapped: Int, declared: Int, enforced: Int, mismatch: Bool) {
            self.contentID = contentID
            self.signer = signer
            self.toolCall = toolCall
            self.annotationMapped = annotationMapped
            self.declared = declared
            self.enforced = enforced
            self.mismatch = mismatch
        }
    }

    /// Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the
    /// signed object with real crypto (Envelope.verify against the composed validator — content id,
    /// ranges, header/body, kind dispatch, profile floor, signature); (2) confirms it is a tier-1
    /// Bridge McpToolCall; (3) parses the tool-call body (rejecting a malformed annotation set); (4)
    /// recomputes the annotation-derived effect from the CARRIED annotations, independent of the
    /// declared effect; (5) resolves the enforced effect to the MORE SEVERE, rejecting under-
    /// declaration. Any failure returns its named error and authorizes nothing (fail-closed).
    ///
    /// PURE-ONLY Swift: Envelope.verify floors a level-0 Ed25519 object (ProfileDowngrade) before its
    /// signature step and refuses an ML-DSA object (Unavailable — the pure port cannot verify ML-DSA),
    /// so the success path needs an ML-DSA level-3 signature the pure tier cannot produce.
    public static func verifyToolCall(_ profile: Int, _ alg: Int, _ pubkey: [UInt8], _ signedObj: [UInt8]) throws -> Resolved {
        let o = try Envelope.verify(profile, alg, pubkey, composedKindValidator, signedObj)
        if o.channel != CHANNEL_BRIDGE || o.kind != KIND_MCP_TOOL_CALL || o.tier != TIER {
            throw NaalpError("ToolCallMalformed", "not a tier-1 Bridge McpToolCall")
        }
        let tc = try toolCallFromBody(o.body)
        let mapped = mapAnnotationsToEffect(tc.annotations)
        let declared = Int(o.effect)  // Envelope.verify already range-checked field 7 to 0..3
        let (enforced, mismatch) = try resolveEnforcedEffect(mapped, declared)
        return Resolved(contentID: o.id ?? [], signer: o.signer, toolCall: tc,
                        annotationMapped: mapped, declared: declared, enforced: enforced, mismatch: mismatch)
    }

    // ---- the per-call approval gate (reuses §7 approval + consume ledger) --------------------------

    /// Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
    /// EXACT call binding content id (tool_id + args_id) — so it satisfies neither a call with different
    /// arguments nor a call whose tool description changed (Requirement 6.1) — its granted effect must
    /// cover the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it is consumed
    /// single-use by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror the spine:
    /// a non-matching or under-granting approval denies ApprovalRequired with no ledger append; an
    /// already-spent approval denies AlreadyConsumed; the consume (the single state change) happens only
    /// when every check holds. `verify` is the injected approval-signature verifier (Ed25519 here).
    public static func authorizeCall(_ r: Resolved, _ appr: Approval.ApprovalRecord, _ verify: Approval.Verify,
                                     _ apprSig: [UInt8], _ by: String, _ now: UInt64, _ ledger: Approval.Ledger) throws {
        let callCID = try r.toolCall.callBinding().contentId()
        do {
            try Approval.verifyApproval(appr, verify, apprSig, callCID, now)
        } catch let e as NaalpError where e.kind == "ApprovalMismatch" {
            // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
            throw NaalpError("ApprovalRequired", "approval does not bind this exact call")
        }
        if !Policy.authorizes(Int(appr.grant), r.enforced) {
            throw NaalpError("ApprovalRequired", "the approval's granted effect does not cover the call")
        }
        _ = try ledger.consume(try appr.id(), by)  // AlreadyConsumed on replay (fail-closed, no double-spend)
    }
}
