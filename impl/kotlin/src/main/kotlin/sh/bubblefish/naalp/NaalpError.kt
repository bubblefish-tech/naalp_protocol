// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * The N-AALP error object and the numeric error-code registry (design.md §3.5, R3.3/R3.4, T3.3).
 *
 * The naalp-error object is the Control/Error body (channel 0x0000, kind 3, effect read_only) that
 * carries one fail-closed rejection reason as `{1:code, 2:name, ?3:detail, ?4:subject}`. The
 * registry is the ordered 129-entry name<->code table [NAMES] (the code for `NAMES[i]` is `i+1`; 0
 * is reserved). [NAMES] is the single source the machine-readable registry
 * (vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are generated to match, and
 * scripts/registry_drift.py asserts the three agree; the table itself is graded against the
 * non-circular oracle by the error.name_for_code conformance op.
 *
 * Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
 * code whose name disagrees with the registry is rejected Malformed (the code is authoritative —
 * the strengthening direction); a code outside the registry is opaque and non-fatal (the name is
 * diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
 *
 * Ported from impl/go/naalperror (cross-read against impl/rust/src/naalperror.rs). The registry
 * order is copied verbatim from the Go reference — it is the fields-of-record authority for every
 * code, so it must not be reordered independently.
 */
object NaalpError {

    /** Top of the RFC-Required standards range; codes >= 0x8000 are private-use. */
    const val STANDARDS_MAX: Long = 0x7FFF

    /**
     * The ordered error-code registry: the code for `NAMES[i]` is `i+1` (0 is reserved and MUST NOT
     * appear on the wire). Order is the fields-of-record authority for every code (§3.5). Copied
     * verbatim from impl/go/naalperror/naalperror.go — do not reorder.
     */
    val NAMES: List<String> = listOf(
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
        // Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
        "EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
        "TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed", "HazardMalformed", "HazardNotCovered", "HazardUnknown",
    )

    private val CODE_BY_NAME: Map<String, Long> =
        NAMES.withIndex().associate { (i, n) -> n to (i + 1).toLong() }

    /**
     * The registered name for [code] and whether [code] is registered. A code of 0, or any value
     * past the registered range, is unregistered (opaque per the open-registry rule).
     */
    fun nameForCode(code: Long): kotlin.Pair<String, Boolean> {
        if (code in 1..NAMES.size.toLong()) {
            return NAMES[(code - 1).toInt()] to true
        }
        return "" to false
    }

    /** The registered code for [name], or null when [name] is unregistered. */
    fun codeForName(name: String): Long? = CODE_BY_NAME[name]

    /** A decoded naalp-error body. */
    class Object(
        val code: Long,
        val name: String,
        val detail: String, // "" if field 3 absent
        val subject: ByteArray?, // null if field 4 absent
    )

    /**
     * Deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body `{1:code, 2:name, ?3:detail,
     * ?4:subject}`. `detail == ""` omits field 3; `subject == null` omits field 4. The integer keys
     * 1..4 are already in canonical ascending order.
     */
    fun encode(code: Long, name: String, detail: String, subject: ByteArray?): ByteArray {
        val pairs = ArrayList<Cbor.Pair>(4)
        pairs.add(Cbor.Pair(Cbor.U(1), Cbor.U(code)))
        pairs.add(Cbor.Pair(Cbor.U(2), Cbor.T(name)))
        if (detail.isNotEmpty()) {
            pairs.add(Cbor.Pair(Cbor.U(3), Cbor.T(detail)))
        }
        if (subject != null) {
            pairs.add(Cbor.Pair(Cbor.U(4), Cbor.B(subject)))
        }
        return Cbor.encode(Cbor.M(pairs))
    }

    /**
     * Parse a naalp-error body and enforce the dual-carriage rules. A structurally malformed body
     * (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
     * rejected Malformed. A registered code whose name disagrees with the registry is rejected
     * Malformed (the code is authoritative). An unregistered code is accepted opaque (name
     * diagnostic only).
     */
    fun decode(data: ByteArray): Object {
        val v = try {
            Cbor.decode(data)
        } catch (e: NaalpException) {
            throw NaalpException("Malformed", "non-canonical naalp-error body: ${e.kind}")
        }
        if (v !is Cbor.M) throw NaalpException("Malformed", "naalp-error body is not a map")
        var code: Long? = null
        var name: String? = null
        var detail = ""
        var subject: ByteArray? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("Malformed", "naalp-error field key is not an unsigned integer")
            when (k.v) {
                1L -> {
                    val c = p.v as? Cbor.U ?: throw NaalpException("Malformed", "code field is not an unsigned integer")
                    code = c.v
                }
                2L -> {
                    val n = p.v as? Cbor.T ?: throw NaalpException("Malformed", "name field is not a text string")
                    name = n.v
                }
                3L -> {
                    val d = p.v as? Cbor.T ?: throw NaalpException("Malformed", "detail field is not a text string")
                    detail = d.v
                }
                4L -> {
                    val s = p.v as? Cbor.B ?: throw NaalpException("Malformed", "subject field is not a byte string")
                    subject = s.v
                }
                else -> throw NaalpException("Malformed", "unknown naalp-error field key ${k.v}") // closed grammar
            }
        }
        if (code == null || name == null) {
            throw NaalpException("Malformed", "naalp-error body missing code or name")
        }
        val (regName, registered) = nameForCode(code)
        if (registered && regName != name) {
            throw NaalpException("Malformed", "registered code disagrees with carried name")
        }
        return Object(code, name, detail, subject)
    }
}
