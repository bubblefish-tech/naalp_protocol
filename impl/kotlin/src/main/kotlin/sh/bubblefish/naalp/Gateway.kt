// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * N-AALP C21 portable gateway-decision object for the Kotlin SDK (design.md §24; R-GW-1..6).
 *
 * A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as PORTABLE
 * EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18 signed
 * description, is that authority lives in the SIGNED BYTES, never in the connection or the host that
 * served them: [verifyDecision] takes NO serving-party/connection identity, so the same signed decision
 * RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the third-party re-serve
 * property). It introduces NO new envelope, encoding, signature, identity, or audit mechanism: the
 * object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5 effect lattice and the
 * T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY — never a policy language. Every
 * check is fail-closed: a failing object is rejected whole, throws its named error, and causes no state
 * change. An independent transcription of impl/go/gateway, graded against the shared
 * vectors/gateway/cases.json.
 *
 * CRYPTO SCOPE: Kotlin signs and verifies with real deterministic FIPS-204 ML-DSA-65 (BouncyCastle), so
 * [signDecision]/[verifyDecision] are the full crypto surface — the signed object is byte-identical to
 * the Go and Rust references, and the third-party re-serve property is demonstrated with real
 * signatures rather than a pure-only stand-in.
 */
object Gateway {
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    const val HEAD_SIZE = 48

    /** The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision). */
    const val DECISION_ALLOW = 0L // the gateway allows the action
    const val DECISION_DENY = 1L  // the gateway denies the action
    const val DECISION_HOLD = 2L  // the gateway holds the action pending a further step

    /** decision code -> name (diagnostics); an unknown code has no entry. */
    private val DECISION_NAMES: Map<Long, String> =
        mapOf(DECISION_ALLOW to "allow", DECISION_DENY to "deny", DECISION_HOLD to "hold")

    /** Reports whether [code] is one of the closed decision codes. */
    fun isKnownDecision(code: Long): Boolean = DECISION_NAMES.containsKey(code)

    /** The decision name, or "unknown". */
    fun decisionName(code: Long): String = DECISION_NAMES[code] ?: "unknown"

    // ---- ordering-disclosure embeddable group (design.md section 26.3) ------------------------
    //
    // `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
    // ORDER, and from which observational domain. It is carried as a field inside naalp-decision-
    // record (mandatory, field 5), naalp-egress-attestation (optional, field 6), and naalp-gateway-
    // decision (optional, field 5) -- never as a top-level object of its own, so it has no
    // head()/id() of its own; it is embedded directly as a nested CBOR map value.

    /** Ordering-basis codes -- the closed set (design.md section 26.3). */
    const val ORDERING_CORRESPONDENCE_ONLY = 0L // the record orders only its own two-party construction (the weakest claim)
    const val ORDERING_SINGLE_BOUNDARY = 1L     // one boundary observed both terms and is named
    const val ORDERING_EXTERNAL_MECHANISM = 2L  // an external sequencing mechanism is named

    private val ORDERING_BASIS_NAMES: Map<Long, String> = mapOf(
        ORDERING_CORRESPONDENCE_ONLY to "correspondence-only",
        ORDERING_SINGLE_BOUNDARY to "single-boundary",
        ORDERING_EXTERNAL_MECHANISM to "external-mechanism"
    )

    /** Reports whether [code] is one of the closed ordering-basis codes. */
    fun isKnownOrderingBasis(code: Long): Boolean = ORDERING_BASIS_NAMES.containsKey(code)

    /** The ordering-basis name, or "unknown". */
    fun orderingBasisName(code: Long): String = ORDERING_BASIS_NAMES[code] ?: "unknown"

    /** Enforcement-disposition codes -- the closed set (design.md section 26.4). */
    const val ENFORCEMENT_ENFORCED = 1L // the producer states it actually enforces this outcome
    const val ENFORCEMENT_ADVISED = 2L  // the producer's own unverifiable self-account that it only advises

    /** Term-disposition kind codes -- reused unchanged from the section 2.5.4 producing-boundary kind vocabulary. */
    const val TERM_OBSERVED = 1L // the term was observed first-hand
    const val TERM_REPORTED = 2L // the term was reported, relayed from a named source

    /** Builds a `key -> value` map from a decoded CBOR map's pairs, keyed by the integer value of any
     * [Cbor.U] key (mirroring the Go/Python/Java embedded-field accessor field(m, k): a key that is
     * not a [Cbor.U] simply does not match -- it never causes rejection here). The strict canonical
     * decoder has already ruled out duplicate keys, so this is a safe 1:1 mapping. */
    private fun fieldsOf(m: Cbor.M): Map<Long, Cbor.Value> {
        val fields = HashMap<Long, Cbor.Value>()
        for (p in m.pairs) {
            val k = p.k
            if (k is Cbor.U) fields[k.v] = p.v
        }
        return fields
    }

    /**
     * The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md section
     * 26.3). It is never a top-level signed object; it is always a field inside another record. The
     * zero value (basis=correspondence-only, no boundary/mechanism/relation) is the weakest claim and
     * is exactly what an ABSENT optional ordering-disclosure field reads as.
     */
    class OrderingDisclosure(
        val basis: Long,
        boundary: ByteArray = ByteArray(0),
        mechanism: ByteArray = ByteArray(0),
        relation: ByteArray = ByteArray(0)
    ) {
        val boundary: ByteArray = boundary.copyOf()   // present iff basis == ORDERING_SINGLE_BOUNDARY
        val mechanism: ByteArray = mechanism.copyOf() // present iff basis == ORDERING_EXTERNAL_MECHANISM
        val relation: ByteArray = relation.copyOf()   // present ONLY when basis == ORDERING_EXTERNAL_MECHANISM (optional even then)

        /** Returns self as a nested CBOR map VALUE (never top-level -- always embedded as a field
         * inside its carrying record, so it has no bytes()/head()/id() of its own). */
        fun toCbor(): Cbor.M {
            val pairs = mutableListOf(Cbor.Pair(Cbor.U(1), Cbor.U(basis)))
            if (boundary.isNotEmpty()) pairs.add(Cbor.Pair(Cbor.U(2), Cbor.B(boundary)))
            if (mechanism.isNotEmpty()) pairs.add(Cbor.Pair(Cbor.U(3), Cbor.B(mechanism)))
            if (relation.isNotEmpty()) pairs.add(Cbor.Pair(Cbor.U(4), Cbor.B(relation)))
            return Cbor.M(pairs)
        }

        /**
         * Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the basis-conditioned
         * field well-formedness rule (design.md section 26.3, native and fail-closed -- any violation
         * rejects the whole carrying record, OrderingDisclosureMalformed). UnknownOrderingBasis is
         * checked and thrown FIRST: an out-of-set basis is never additionally reported as malformed.
         */
        fun validate() {
            if (!isKnownOrderingBasis(basis)) {
                throw NaalpException(
                    "UnknownOrderingBasis",
                    "ordering-disclosure basis is outside the closed set correspondence-only/single-boundary/external-mechanism"
                )
            }
            when (basis) {
                ORDERING_CORRESPONDENCE_ONLY -> if (boundary.isNotEmpty() || mechanism.isNotEmpty() || relation.isNotEmpty()) {
                    throw NaalpException("OrderingDisclosureMalformed", "correspondence-only requires keys 2/3/4 absent")
                }
                ORDERING_SINGLE_BOUNDARY -> if (boundary.isEmpty() || mechanism.isNotEmpty() || relation.isNotEmpty()) {
                    throw NaalpException("OrderingDisclosureMalformed", "single-boundary requires key 2 present, keys 3/4 absent")
                }
                ORDERING_EXTERNAL_MECHANISM -> if (boundary.isNotEmpty() || mechanism.isEmpty()) {
                    throw NaalpException("OrderingDisclosureMalformed", "external-mechanism requires key 2 absent, key 3 present")
                }
            }
        }
    }

    /** The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
     * ordering-disclosure field. */
    fun correspondenceOnly(): OrderingDisclosure = OrderingDisclosure(ORDERING_CORRESPONDENCE_ONLY)

    /** Decodes a nested ordering-disclosure map value. Returns null on any wrong shape, including an
     * optional key present under the WRONG CBOR type (never silently treated as absent). */
    private fun orderingFromCbor(v: Cbor.Value): OrderingDisclosure? {
        if (v !is Cbor.M) return null
        val f = fieldsOf(v)
        val basisV = f[1L]
        if (basisV !is Cbor.U) return null
        var boundary = ByteArray(0)
        var mechanism = ByteArray(0)
        var relation = ByteArray(0)
        if (f.containsKey(2L)) {
            val b = f[2L]
            if (b !is Cbor.B) return null
            boundary = b.v
        }
        if (f.containsKey(3L)) {
            val b = f[3L]
            if (b !is Cbor.B) return null
            mechanism = b.v
        }
        if (f.containsKey(4L)) {
            val b = f[4L]
            if (b !is Cbor.B) return null
            relation = b.v
        }
        return OrderingDisclosure(basisV.v, boundary, mechanism, relation)
    }

    /** The embeddable group {1: kind, ?2: source} (design.md section 26.4). [kind] is carried as a
     * plain uint on the wire (the CDDL does not close its value set the way ordering-basis does), so
     * TermDisposition itself validates no closed set -- only naalp-decision-record's own field-6 key
     * set (the record's own field numbers) is fail-closed (TermDispositionMalformed). */
    class TermDisposition(val kind: Long, source: ByteArray = ByteArray(0)) {
        val source: ByteArray = source.copyOf() // present iff kind == TERM_REPORTED

        fun toCbor(): Cbor.M {
            val pairs = mutableListOf(Cbor.Pair(Cbor.U(1), Cbor.U(kind)))
            if (source.isNotEmpty()) pairs.add(Cbor.Pair(Cbor.U(2), Cbor.B(source)))
            return Cbor.M(pairs)
        }
    }

    private fun termDispositionFromCbor(v: Cbor.Value): TermDisposition? {
        if (v !is Cbor.M) return null
        val f = fieldsOf(v)
        val kindV = f[1L]
        if (kindV !is Cbor.U) return null
        var source = ByteArray(0)
        if (f.containsKey(2L)) {
            val b = f[2L]
            if (b !is Cbor.B) return null
            source = b.v
        }
        return TermDisposition(kindV.v, source)
    }

    // ---- ForeignProfilePin: GatewayDecision field 6, R8 -----------------------------------------

    /** The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
     * GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the
     * foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
     * time -- binding the reference, not just the class. Both fields are mandatory tstr; the group
     * carries no other keys. It is never a top-level signed object -- always embedded as field 6 of
     * its carrying naalp-gateway-decision, so it has no head()/id() of its own (mirroring
     * OrderingDisclosure). */
    class ForeignProfilePin internal constructor(val id: String, val revision: String, private val unknownField: Boolean) {
        // unknownField: an unrecognized key besides 1/2 was present in the decoded CBOR map

        constructor(id: String, revision: String) : this(id, revision, false)

        /** Returns self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}. */
        fun toCbor(): Cbor.M = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.T(id)),
                Cbor.Pair(Cbor.U(2), Cbor.T(revision))
            )
        )

        /** Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are
         * mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or
         * extra field rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed). */
        fun validate() {
            if (id.isEmpty() || revision.isEmpty() || unknownField) {
                throw NaalpException(
                    "ForeignProfileMalformed",
                    "foreign-profile-pin is not well-formed (id and revision are mandatory tstr, no other keys)"
                )
            }
        }
    }

    /** Decodes a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
     * orderingFromCbor: a key present under the WRONG CBOR type fails decode (returns null, never
     * silently treated as absent); a key that is simply ABSENT decodes to the empty string, leaving
     * the mandatory-presence check to validate(). A key besides 1/2 marks the group's unknown-field
     * flag, also caught by validate() -- the closed 2-key set is enforced semantically, not by
     * refusing to decode a map that merely carries an extra key. */
    private fun foreignProfileFromCbor(v: Cbor.Value): ForeignProfilePin? {
        if (v !is Cbor.M) return null
        var id = ""
        var revision = ""
        var unknown = false
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L) {
                val t = p.v
                if (t !is Cbor.T) return null
                id = t.v
            } else if (k is Cbor.U && k.v == 2L) {
                val t = p.v
                if (t !is Cbor.T) return null
                revision = t.v
            } else {
                unknown = true
            }
        }
        return ForeignProfilePin(id, revision, unknown)
    }

    /**
     * A signed decision an enforcement gateway emits as portable evidence. [decision] is the closed-set
     * outcome; [action] is the content id of the action decided about; [policy] is the opaque
     * deciding-policy identity (a name, not a program); [effect] is the action's C5 class. [ordering]
     * (field 5, R1) and [foreignProfile] (field 6, R8) are OPTIONAL: `null` reads exactly as an absent
     * field (correspondence-only ordering / no foreign-profile pin) -- never a stronger claim inferred
     * from silence.
     */
    class GatewayDecision(
        val decision: Long,
        action: ByteArray,
        policy: ByteArray,
        val effect: Long,
        val ordering: OrderingDisclosure? = null,
        val foreignProfile: ForeignProfilePin? = null
    ) {
        val action: ByteArray = action.copyOf()
        val policy: ByteArray = policy.copyOf()

        /** Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
         * ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when null (the same omit-when-absent
         * precedent as naalp-decision-record's optional fields 3/6/7). */
        fun bytes(): ByteArray {
            val pairs = mutableListOf(
                Cbor.Pair(Cbor.U(1), Cbor.U(decision)),
                Cbor.Pair(Cbor.U(2), Cbor.B(action)),
                Cbor.Pair(Cbor.U(3), Cbor.B(policy)),
                Cbor.Pair(Cbor.U(4), Cbor.U(effect))
            )
            ordering?.let { pairs.add(Cbor.Pair(Cbor.U(5), it.toCbor())) }
            foreignProfile?.let { pairs.add(Cbor.Pair(Cbor.U(6), it.toCbor())) }
            return Cbor.encode(Cbor.M(pairs))
        }

        /** The decision's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())

        /** The C5 effect class, normalized fail-closed: an unrecognized value is destructive (R-6.2). */
        fun effectClass(): Long = Policy.normalizeEffect(effect)
    }

    /**
     * A GatewayDecision that has passed signature verification. It carries NOTHING about who served the
     * bytes — the authority is the signature, so the resolved evidence is identical regardless of the
     * serving party (the third-party re-serve property).
     */
    class ResolvedDecision(val decision: Long, val action: ByteArray, val policy: ByteArray, val effect: Long)

    /**
     * Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision code
     * against the closed set — that is [verifyDecision]'s job — so a decision carrying an unknown code
     * can be represented (and then rejected). Fail-closed on a malformed shape: a non-canonical body, a
     * non-map, or an absent/wrong-typed field 1-4 throws GwMalformed.
     */
    fun parseDecision(b: ByteArray): GatewayDecision {
        val v: Cbor.Value = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("GwMalformed", "decision body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) {
            throw NaalpException("GwMalformed", "decision body is not a map")
        }
        val fields = fieldsOf(v)
        val dec = fields[1L]
        val action = fields[2L]
        val pol = fields[3L]
        val eff = fields[4L]
        if (dec !is Cbor.U || action !is Cbor.B || pol !is Cbor.B || eff !is Cbor.U) {
            throw NaalpException("GwMalformed", "decision body missing or wrong-typed field 1-4")
        }
        var ordering: OrderingDisclosure? = null
        if (fields.containsKey(5L)) {
            ordering = orderingFromCbor(fields[5L]!!)
                ?: throw NaalpException("GwMalformed", "field 5 (ordering) is present but malformed")
        }
        var foreignProfile: ForeignProfilePin? = null
        if (fields.containsKey(6L)) {
            foreignProfile = foreignProfileFromCbor(fields[6L]!!)
                ?: throw NaalpException("GwMalformed", "field 6 (foreign-profile) is present but malformed")
        }
        return GatewayDecision(dec.v, action.v, pol.v, eff.v, ordering, foreignProfile)
    }

    /** The bare {1: alg} COSE_Sign1 protected header (§4), as the reference's cose.Sign1 emits. */
    fun gatewayProtectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    /**
     * Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway with a real
     * deterministic FIPS-204 ML-DSA key derived from [seed].
     */
    fun signDecision(d: GatewayDecision, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), d.bytes())

    /** Read the alg (label 1) value from an encoded protected header. */
    private fun algFromProtected(prot: ByteArray): Int {
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) {
            throw NaalpException("GwMalformed", "protected header is not a map")
        }
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L) {
                val value = p.v
                if (value is Cbor.N) return value.v.toInt()
                if (value is Cbor.U) return value.v.toInt()
            }
        }
        throw NaalpException("GwMalformed", "protected header has no alg")
    }

    /**
     * Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the signed
     * object under the profile with real crypto (signature, alg registry, profile floor) against the
     * gateway's key; (2) reconstructs it from the signed bytes; and (3) validates the decision code
     * against the closed set (UnknownGatewayDecision). It takes NO serving-party or connection identity:
     * the authority is the signature over the bytes, so the same [obj] yields an identical
     * ResolvedDecision whether the gateway or an unrelated third party served it. Any failure throws its
     * named error and resolves nothing (fail-closed).
     */
    fun verifyDecision(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ResolvedDecision {
        val parts = Cose.parseSign1Raw(obj) // [protected, payload, signature]
        val halg = algFromProtected(parts[0])
        val (level, known) = Cose.algLevel(halg)
        if (!known) {
            throw NaalpException("UnknownAlg", "unregistered alg $halg")
        }
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (halg != alg) {
            throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        }
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        val d = parseDecision(parts[1])
        if (!isKnownDecision(d.decision)) {
            throw NaalpException("UnknownGatewayDecision", "decision code ${d.decision} outside the closed set")
        }
        d.ordering?.validate()
        d.foreignProfile?.validate()
        return ResolvedDecision(d.decision, d.action.copyOf(), d.policy.copyOf(), Policy.normalizeEffect(d.effect))
    }

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    // =================================================================================================
    // Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint), ported
    // from impl/go/gateway/{decision_record,checkpoint,egress_attestation}.go and impl/java's Gateway,
    // graded against the shared vectors/{decision_record,checkpoint,egress_attestation}/cases.json plus
    // gateway/cases.json's optional_fields{} block (the ordering-disclosure/term-disposition/foreign-
    // profile-pin groups above already carry R1/R8).
    // =================================================================================================

    // ---- naalp-decision-record: S1, the full governed-decision accountability record -------------
    //
    // A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
    // action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
    // triple (section 26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content
    // ids); GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-
    // BY-T (established off-record by inclusion under a witnessed naalp-checkpoint-root). The record
    // is deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time
    // properties are POSITIONAL, never a self-asserted timestamp.

    /** The governed-decision accountability record (design.md section 26.4). [action] is the content
     * id of the action decided about; [governing] is the closed governing condition set, content ids,
     * in the clear (may be empty); [consume] is OPTIONAL field 3 (content id of the consume-receipt
     * spent at decision time; empty == absent); [outcome] is field 4 (allow/deny/hold, reuses the
     * closed gw-decision set); [ordering] is field 5, MANDATORY (no silent default -- every record
     * states its ordering basis); [terms] is OPTIONAL field 6 (per-term observed/reported, keyed by
     * this record's OWN field numbers 1..5; empty == absent); [enforcement] is OPTIONAL field 7
     * (enforced(1)/advised(2); 0 == absent). */
    class DecisionRecord(
        action: ByteArray,
        governing: List<ByteArray>,
        val outcome: Long,
        val ordering: OrderingDisclosure,
        consume: ByteArray = ByteArray(0),
        terms: Map<Long, TermDisposition> = emptyMap(),
        val enforcement: Long = 0L
    ) {
        val action: ByteArray = action.copyOf()
        val governing: List<ByteArray> = governing.map { it.copyOf() }
        val consume: ByteArray = consume.copyOf()
        val terms: Map<Long, TermDisposition> = HashMap(terms)

        /** Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
         * ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms
         * empty, enforcement zero) -- the omit-when-absent precedent (naalp-approval ?6:audience). */
        fun bytes(): ByteArray {
            val pairs = mutableListOf<Cbor.Pair>()
            pairs.add(Cbor.Pair(Cbor.U(1), Cbor.B(action)))
            pairs.add(Cbor.Pair(Cbor.U(2), Cbor.A(governing.map { Cbor.B(it) })))
            if (consume.isNotEmpty()) {
                pairs.add(Cbor.Pair(Cbor.U(3), Cbor.B(consume)))
            }
            pairs.add(Cbor.Pair(Cbor.U(4), Cbor.U(outcome)))
            pairs.add(Cbor.Pair(Cbor.U(5), ordering.toCbor()))
            if (terms.isNotEmpty()) {
                val tpairs = terms.entries.map { (k, v) -> Cbor.Pair(Cbor.U(k), v.toCbor()) }
                pairs.add(Cbor.Pair(Cbor.U(6), Cbor.M(tpairs)))
            }
            if (enforcement != 0L) {
                pairs.add(Cbor.Pair(Cbor.U(7), Cbor.U(enforcement)))
            }
            return Cbor.encode(Cbor.M(pairs))
        }

        /** The record's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The record's T1 content-id (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    /**
     * Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
     * (mandatory-field presence and CBOR type); it does NOT validate the outcome against the closed
     * gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the deny/hold-
     * with-consume rule, or the terms key set -- see [validateDecisionRecord]. Fail-closed on any
     * malformed shape (DecisionMalformed).
     */
    fun parseDecisionRecord(b: ByteArray): DecisionRecord {
        val v: Cbor.Value = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("DecisionMalformed", "decision-record body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) {
            throw NaalpException("DecisionMalformed", "decision-record body is not a map")
        }
        val fields = fieldsOf(v)
        val actionV = fields[1L]
        val govV = fields[2L]
        if (actionV !is Cbor.B || govV !is Cbor.A) {
            throw NaalpException("DecisionMalformed", "missing or wrong-typed field 1/2")
        }
        val governing = ArrayList<ByteArray>()
        for (item in govV.items) {
            if (item !is Cbor.B) {
                throw NaalpException("DecisionMalformed", "governing array element not a bstr")
            }
            governing.add(item.v)
        }
        var consume = ByteArray(0)
        if (fields.containsKey(3L)) {
            val cv = fields[3L]
            if (cv !is Cbor.B) {
                throw NaalpException("DecisionMalformed", "field 3 (consume) wrong type")
            }
            consume = cv.v
        }
        val outcomeV = fields[4L]
        if (outcomeV !is Cbor.U) {
            throw NaalpException("DecisionMalformed", "missing or wrong-typed field 4 (outcome)")
        }
        if (!fields.containsKey(5L)) {
            throw NaalpException("DecisionMalformed", "missing mandatory field 5 (ordering)")
        }
        val ordering = orderingFromCbor(fields[5L]!!)
            ?: throw NaalpException("DecisionMalformed", "field 5 (ordering) malformed")
        val terms = HashMap<Long, TermDisposition>()
        if (fields.containsKey(6L)) {
            val tv = fields[6L]
            if (tv !is Cbor.M) {
                throw NaalpException("DecisionMalformed", "field 6 (terms) wrong type")
            }
            for (p in tv.pairs) {
                val ku = p.k
                if (ku !is Cbor.U) {
                    throw NaalpException("DecisionMalformed", "terms map key not a uint")
                }
                val td = termDispositionFromCbor(p.v)
                    ?: throw NaalpException("DecisionMalformed", "terms map value malformed")
                terms[ku.v] = td
            }
        }
        var enforcement = 0L
        if (fields.containsKey(7L)) {
            val ev = fields[7L]
            if (ev !is Cbor.U) {
                throw NaalpException("DecisionMalformed", "field 7 (enforcement) wrong type")
            }
            enforcement = ev.v
        }
        return DecisionRecord(actionV.v, governing, outcomeV.v, ordering, consume, terms, enforcement)
    }

    /** Reports whether [k] is one of the record's own field numbers 1..5 -- the only valid keys for
     * the field-6 terms map (design.md section 26.4; TermDispositionMalformed otherwise). */
    private fun validDecisionRecordTermKey(k: Long): Boolean = k in 1..5

    /**
     * Performs the semantic, closed-set, and native well-formedness checks [parseDecisionRecord]
     * deliberately does not (mirroring [verifyDecision]'s parse/verify split):
     * 1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
     * 2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
     *    OrderingDisclosureMalformed) -- checked BEFORE the deny/hold-consume rule so a record whose
     *    ordering is itself malformed is never additionally reported as a consume violation.
     * 3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
     *    (DecisionMalformed) -- nothing was consumed, so a value here would assert authority spent
     *    for an action the record's own outcome says was not taken.
     * 4. Every terms map key must be one of the record's own field numbers 1..5
     *    (TermDispositionMalformed).
     */
    fun validateDecisionRecord(d: DecisionRecord) {
        if (!isKnownDecision(d.outcome)) {
            throw NaalpException("UnknownGatewayDecision", "decision-record outcome ${d.outcome} outside the closed set")
        }
        d.ordering.validate()
        if (d.outcome != DECISION_ALLOW && d.consume.isNotEmpty()) {
            throw NaalpException("DecisionMalformed", "a deny/hold outcome must not carry a field-3 consume reference")
        }
        for (k in d.terms.keys) {
            if (!validDecisionRecordTermKey(k)) {
                throw NaalpException("TermDispositionMalformed", "a terms map key is outside the record's own field set 1..5")
            }
        }
    }

    /** Produce the tagged COSE_Sign1 object over the record body, signed by the governed decision point. */
    fun signDecisionRecord(d: DecisionRecord, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), d.bytes())

    /** A DecisionRecord that has passed signature verification and full semantic validation. */
    class ResolvedDecisionRecord(
        val action: ByteArray,
        val governing: List<ByteArray>,
        val consume: ByteArray,
        val outcome: Long,
        val ordering: OrderingDisclosure,
        val terms: Map<Long, TermDisposition>,
        val enforcement: Long
    )

    /**
     * Verify a decision record end-to-end: (1) the signed object under the profile with real crypto;
     * (2) structural reconstruction ([parseDecisionRecord]); and (3) full semantic validation
     * ([validateDecisionRecord]). It takes no serving-party or connection identity -- the authority is
     * the signature over the bytes, mirroring [verifyDecision]. Any failure throws its named error and
     * resolves nothing (fail-closed).
     */
    fun verifyDecisionRecord(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ResolvedDecisionRecord {
        val parts = Cose.parseSign1Raw(obj)
        val halg = algFromProtected(parts[0])
        val (level, known) = Cose.algLevel(halg)
        if (!known) {
            throw NaalpException("UnknownAlg", "unregistered alg $halg")
        }
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (halg != alg) {
            throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        }
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        val d = parseDecisionRecord(parts[1])
        validateDecisionRecord(d)
        return ResolvedDecisionRecord(
            d.action.copyOf(), ArrayList(d.governing), d.consume.copyOf(), d.outcome, d.ordering, d.terms, d.enforcement
        )
    }

    // ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 -----------------
    //
    // S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
    // (design.md section 26.5). Tree construction follows RFC 9162
    // (https://www.rfc-editor.org/rfc/rfc9162.html) section 2.1 EXACTLY, SHA-384-profiled: leaf hash
    // = HASH(0x00 || leaf); interior node hash = HASH(0x01 || left || right); MTH({}) = HASH() (the
    // empty hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the
    // largest power of two k < n. Section 2.1.2's PATH(m, D[n]) recursion (leaf-to-root sibling
    // order) generates the audit path; section 2.1.3.1's inverse recursion recomputes the root from
    // (leaf, index, size, path) and compares against the named root (InclusionProofInvalid on
    // mismatch, fail-closed).

    /** The width of a head/content-id digest for [genesisPrev]. */
    fun genesisPrev(): ByteArray = ByteArray(HEAD_SIZE)

    /** A log operator's signed Merkle tree head over a leaf set of record content ids (design.md
     * section 26.5). */
    class CheckpointRoot(log: ByteArray, val size: Long, root: ByteArray, prev: ByteArray, val at: Long) {
        val log: ByteArray = log.copyOf()
        val root: ByteArray = root.copyOf()
        val prev: ByteArray = prev.copyOf()

        /** Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(log)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(size)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(root)),
                    Cbor.Pair(Cbor.U(4), Cbor.B(prev)),
                    Cbor.Pair(Cbor.U(5), Cbor.U(at))
                )
            )
        )

        /** The checkpoint's SHA-384 head (48 octets) -- the `prev` the NEXT checkpoint chains from. */
        fun head(): ByteArray = sha384(bytes())

        /** The checkpoint's T1 content-id (50 octets) -- what an inclusion proof's `root` field and a
         * witness-cosign's `root` field both name. */
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    /** Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
     * (CheckpointMalformed): every one of the five fields is mandatory. */
    fun parseCheckpointRoot(b: ByteArray): CheckpointRoot {
        val v: Cbor.Value = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("CheckpointMalformed", "checkpoint-root body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) {
            throw NaalpException("CheckpointMalformed", "checkpoint-root body is not a map")
        }
        val f = fieldsOf(v)
        val log = f[1L]
        val size = f[2L]
        val root = f[3L]
        val prev = f[4L]
        val at = f[5L]
        if (log !is Cbor.B || size !is Cbor.U || root !is Cbor.B || prev !is Cbor.B || at !is Cbor.U) {
            throw NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-5")
        }
        return CheckpointRoot(log.v, size.v, root.v, prev.v, at.v)
    }

    /** Produce the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator. */
    fun signCheckpointRoot(c: CheckpointRoot, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), c.bytes())

    /** A witness's countersignature over one exact checkpoint by content id (design.md section
     * 26.5). Whether the witness's observational domain is genuinely distinct from both parties to
     * the decisions the checkpoint covers is a structural deployment fact checkable in substance at
     * T+n -- the wire supplies the hook; it does not manufacture the independence itself. */
    class WitnessCosign(witness: ByteArray, root: ByteArray, val at: Long) {
        val witness: ByteArray = witness.copyOf()
        val root: ByteArray = root.copyOf()

        /** Deterministic-CBOR encoding {1:witness, 2:root, 3:at}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(witness)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(root)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(at))
                )
            )
        )

        /** The cosign's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The cosign's T1 content-id (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    /** Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape:
     * every one of the three fields is mandatory. */
    fun parseWitnessCosign(b: ByteArray): WitnessCosign {
        val v: Cbor.Value = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("CheckpointMalformed", "witness-cosign body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) {
            throw NaalpException("CheckpointMalformed", "witness-cosign body is not a map")
        }
        val f = fieldsOf(v)
        val witness = f[1L]
        val root = f[2L]
        val at = f[3L]
        if (witness !is Cbor.B || root !is Cbor.B || at !is Cbor.U) {
            throw NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-3")
        }
        return WitnessCosign(witness.v, root.v, at.v)
    }

    /** Produce the tagged COSE_Sign1 object over the cosign body, signed by the witness. */
    fun signWitnessCosign(w: WitnessCosign, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), w.bytes())

    /** Checks that [w] names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md
     * section 26.5): `w.root` must equal [accompaniedCheckpointId], the content id of the
     * naalp-checkpoint-root object [w] claims to cosign. Fail-closed. */
    fun validateWitnessCosign(w: WitnessCosign, accompaniedCheckpointId: ByteArray) {
        if (!w.root.contentEquals(accompaniedCheckpointId)) {
            throw NaalpException(
                "WitnessRootMismatch",
                "witness-cosign names a root content id that does not match the checkpoint it accompanies"
            )
        }
    }

    /** Proves one record's content id existed as a leaf under a named checkpoint (design.md section
     * 26.5, RFC 9162 section 2.1.3.1). */
    class InclusionProof(root: ByteArray, leaf: ByteArray, val index: Long, path: List<ByteArray>) {
        val root: ByteArray = root.copyOf()
        val leaf: ByteArray = leaf.copyOf()
        val path: List<ByteArray> = path.map { it.copyOf() }

        /** Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(root)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(leaf)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(index)),
                    Cbor.Pair(Cbor.U(4), Cbor.A(path.map { Cbor.B(it) }))
                )
            )
        )

        /** The proof's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The proof's T1 content-id (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    /** Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
     * every one of the four fields is mandatory. */
    fun parseInclusionProof(b: ByteArray): InclusionProof {
        val v: Cbor.Value = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("CheckpointMalformed", "inclusion-proof body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) {
            throw NaalpException("CheckpointMalformed", "inclusion-proof body is not a map")
        }
        val f = fieldsOf(v)
        val root = f[1L]
        val leaf = f[2L]
        val index = f[3L]
        val pathV = f[4L]
        if (root !is Cbor.B || leaf !is Cbor.B || index !is Cbor.U || pathV !is Cbor.A) {
            throw NaalpException("CheckpointMalformed", "missing or wrong-typed field 1-4")
        }
        val path = ArrayList<ByteArray>()
        for (item in pathV.items) {
            if (item !is Cbor.B) {
                throw NaalpException("CheckpointMalformed", "path array element not a bstr")
            }
            path.add(item.v)
        }
        return InclusionProof(root.v, leaf.v, index.v, path)
    }

    // ---- RFC 9162 section 2.1 Merkle tree math (SHA-384-profiled) ---------------------------------

    /** leaf_hash = HASH(0x00 || leaf) (RFC 9162 section 2.1's LEAF_HASH, leaf/interior domain separation). */
    private fun leafHash(leaf: ByteArray): ByteArray {
        val b = ByteArray(1 + leaf.size)
        b[0] = 0x00
        System.arraycopy(leaf, 0, b, 1, leaf.size)
        return sha384(b)
    }

    /** node_hash = HASH(0x01 || left || right) (RFC 9162 section 2.1's NODE_HASH). */
    private fun nodeHash(l: ByteArray, r: ByteArray): ByteArray {
        val b = ByteArray(1 + l.size + r.size)
        b[0] = 0x01
        System.arraycopy(l, 0, b, 1, l.size)
        System.arraycopy(r, 0, b, 1 + l.size, r.size)
        return sha384(b)
    }

    /** The largest power of two strictly less than n (n > 1), per RFC 9162 section 2.1's k = "the
     * largest power of two smaller than n". */
    private fun largestPowerOfTwoLessThan(n: Int): Int {
        var k = 1
        while (2 * k < n) {
            k *= 2
        }
        return k
    }

    /** Computes MTH(leaves) per RFC 9162 section 2.1: MTH({}) = HASH() (SHA-384 of the empty string);
     * MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
     * power of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied
     * internally -- callers never hash a leaf before calling merkleRoot. `leaves == null` is accepted
     * as the empty list. */
    fun merkleRoot(leaves: List<ByteArray>?): ByteArray {
        val n = leaves?.size ?: 0
        if (n == 0) {
            return sha384(ByteArray(0)) // MTH({}) = HASH(""), the empty-list base case
        }
        if (n == 1) {
            return leafHash(leaves!![0])
        }
        val k = largestPowerOfTwoLessThan(n)
        return nodeHash(merkleRoot(leaves!!.subList(0, k)), merkleRoot(leaves.subList(k, n)))
    }

    /** Internal sentinel: the recursive root recomputation ran out of path entries (or had entries
     * left over) before reaching the single-leaf base case. Always surfaced to callers as
     * InclusionProofInvalid -- never exported. */
    private class PathLengthMismatch : RuntimeException()

    /** Computes the RFC 9162 section 2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling
     * order -- the list's FIRST entry is the leaf's immediate sibling, the LAST is closest to the
     * root, exactly the order naalp-inclusion-proof's `path` field carries). */
    fun generateInclusionProofPath(leaves: List<ByteArray>, index: Int): List<ByteArray> {
        if (index < 0 || index >= leaves.size) {
            throw NaalpException("InclusionProofInvalid", "leaf index out of range")
        }
        return genPath(leaves, index)
    }

    private fun genPath(leaves: List<ByteArray>, index: Int): MutableList<ByteArray> {
        val n = leaves.size
        if (n <= 1) {
            return ArrayList() // PATH(0, {d0}) = {} -- the single-leaf base case
        }
        val k = largestPowerOfTwoLessThan(n)
        val out: MutableList<ByteArray>
        if (index < k) {
            out = genPath(leaves.subList(0, k), index)
            out.add(merkleRoot(leaves.subList(k, n)))
        } else {
            out = genPath(leaves.subList(k, n), index - k)
            out.add(merkleRoot(leaves.subList(0, k)))
        }
        return out
    }

    /** The exact structural inverse of [genPath]: at each level it consumes the LAST remaining path
     * entry (closest to the root) as this level's sibling and recurses into the appropriate half with
     * the entries that remain. */
    private fun recomputeRoot(leafH: ByteArray, index: Int, size: Int, path: List<ByteArray>): ByteArray {
        if (size == 1) {
            if (path.isNotEmpty()) {
                throw PathLengthMismatch()
            }
            return leafH
        }
        if (path.isEmpty()) {
            throw PathLengthMismatch()
        }
        val k = largestPowerOfTwoLessThan(size)
        val last = path[path.size - 1]
        val rest = path.subList(0, path.size - 1)
        return if (index < k) {
            val left = recomputeRoot(leafH, index, k, rest)
            nodeHash(left, last)
        } else {
            val right = recomputeRoot(leafH, index - k, size - k, rest)
            nodeHash(last, right)
        }
    }

    /**
     * Recomputes the audit path bottom-up (RFC 9162 section 2.1.3.1, the inverse of PATH()) from
     * (leaf, index, size, path) and compares the result against root. [size] is the tree size the
     * proof is checked against -- the resolved naalp-checkpoint-root's own `size` field, NOT carried
     * inside naalp-inclusion-proof itself. Fail-closed: any mismatch, out-of-range index, or
     * path-length mismatch is InclusionProofInvalid.
     */
    fun verifyInclusionProof(leaf: ByteArray, index: Long, size: Long, path: List<ByteArray>, root: ByteArray) {
        if (size == 0L || index >= size) {
            throw NaalpException("InclusionProofInvalid", "index out of range for the claimed tree size")
        }
        val got = try {
            recomputeRoot(leafHash(leaf), index.toInt(), size.toInt(), ArrayList(path))
        } catch (e: PathLengthMismatch) {
            throw NaalpException("InclusionProofInvalid", "inclusion path length does not match the claimed tree size")
        }
        if (!got.contentEquals(root)) {
            throw NaalpException("InclusionProofInvalid", "inclusion audit path does not recompute to the named root")
        }
    }

    // ---- naalp-egress-attestation: E6.3 ------------------------------------------------------------
    //
    // A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
    // given effect class, bound to a given audience, crossed an egress boundary at a given time --
    // third-party verifiable WITHOUT the payload. It is a near-clone of GatewayDecision: the gateway
    // is the SIGNER, and verifyEgressAttestation takes NO serving-party or connection identity -- the
    // authority is the signature over the bytes, so the identical attested evidence re-verifies
    // whether the gateway or an unrelated third party serves it. `binding` is a closed set
    // (content_bound/content_free); `digest` is either the T1 content-id of the crossed object
    // (content_bound) or a hiding commitment SHA-384(content_id||salt) (content_free) -- never both;
    // `effect` is the C5 effect class of the crossed object; `audience` is the bound destination
    // (empty-permitted); `at` is the crossing time in epoch milliseconds. Field 6 (`ordering`) is
    // OPTIONAL: ABSENT reads correspondence-only, never a stronger claim inferred from silence.
    //
    // The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which
    // object crossed. egressCommit/openEgressCommitment is the open/verify pair: the gateway (or
    // anyone it later discloses content-id+salt to) can PROVE which object a content_free
    // attestation names, without the attestation bytes themselves ever carrying the content-id.

    const val BINDING_CONTENT_BOUND = 0L // digest is the crossed object's T1 content-id
    const val BINDING_CONTENT_FREE = 1L  // digest is a hiding commitment SHA-384(content_id||salt)

    private val BINDING_NAMES: Map<Long, String> = mapOf(
        BINDING_CONTENT_BOUND to "content_bound", BINDING_CONTENT_FREE to "content_free"
    )

    /** Reports whether [code] is one of the closed binding codes. */
    fun isKnownBinding(code: Long): Boolean = BINDING_NAMES.containsKey(code)

    /** The binding name, or "unknown". */
    fun bindingName(code: Long): String = BINDING_NAMES[code] ?: "unknown"

    /** A signed attestation a gateway/sidecar emits that an object crossed an egress boundary.
     * [binding] selects how [digest] is interpreted (content_bound: the crossed object's T1
     * content-id; content_free: a hiding commitment). [effect] is the crossed object's C5 effect
     * class. [audience] is the bound destination (empty-permitted). [at] is the crossing time, epoch
     * ms. [ordering] is the OPTIONAL field 6: null == ABSENT (reads correspondence-only). */
    class EgressAttestation(
        val binding: Long,
        digest: ByteArray,
        val effect: Long,
        audience: ByteArray,
        val at: Long,
        val ordering: OrderingDisclosure? = null
    ) {
        val digest: ByteArray = digest.copyOf()
        val audience: ByteArray = audience.copyOf()

        /** Deterministic-CBOR encoding {1: binding, 2: digest, 3: effect, 4: audience, 5: at,
         * ?6: ordering}. Field 6 is OMITTED when [ordering] is null. */
        fun bytes(): ByteArray {
            val pairs = mutableListOf(
                Cbor.Pair(Cbor.U(1), Cbor.U(binding)),
                Cbor.Pair(Cbor.U(2), Cbor.B(digest)),
                Cbor.Pair(Cbor.U(3), Cbor.U(effect)),
                Cbor.Pair(Cbor.U(4), Cbor.B(audience)),
                Cbor.Pair(Cbor.U(5), Cbor.U(at))
            )
            ordering?.let { pairs.add(Cbor.Pair(Cbor.U(6), it.toCbor())) }
            return Cbor.encode(Cbor.M(pairs))
        }

        /** The attestation's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The attestation's T1 content-id (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())

        /** The attestation's C5 effect class, normalized fail-closed: a value the evaluator does not
         * recognize is treated as destructive, never as a weaker class. */
        fun effectClass(): Long = Policy.normalizeEffect(effect)
    }

    /**
     * Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
     * code against the closed set -- that is [verifyEgressAttestation]'s job -- so an attestation
     * carrying an unknown binding can be represented (and then rejected). Fail-closed on a malformed
     * shape: every one of the five mandatory fields is required, and a present-but-wrong-typed field
     * 6 fails here too.
     */
    fun parseEgressAttestation(b: ByteArray): EgressAttestation {
        val v: Cbor.Value = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            throw NaalpException("EgMalformed", "egress-attestation body is not well-formed deterministic CBOR")
        }
        if (v !is Cbor.M) {
            throw NaalpException("EgMalformed", "egress-attestation body is not a map")
        }
        val f = fieldsOf(v)
        val binding = f[1L]
        val digest = f[2L]
        val effect = f[3L]
        val audience = f[4L]
        val at = f[5L]
        if (binding !is Cbor.U || digest !is Cbor.B || effect !is Cbor.U || audience !is Cbor.B || at !is Cbor.U) {
            throw NaalpException("EgMalformed", "missing or wrong-typed field 1-5")
        }
        var ordering: OrderingDisclosure? = null
        if (f.containsKey(6L)) {
            ordering = orderingFromCbor(f[6L]!!)
                ?: throw NaalpException("EgMalformed", "field 6 (ordering) is present but malformed")
        }
        return EgressAttestation(binding.v, digest.v, effect.v, audience.v, at.v, ordering)
    }

    /** Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway. */
    fun signEgressAttestation(a: EgressAttestation, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, gatewayProtectedHeader(alg), a.bytes())

    /** An EgressAttestation that has passed signature verification. It carries NOTHING about WHO
     * served the bytes -- the authority is the signature, so the resolved evidence is identical
     * regardless of the serving party (the third-party re-serve property). */
    class ResolvedEgressAttestation(
        val binding: Long,
        val digest: ByteArray,
        val effect: Long,
        val audience: ByteArray,
        val at: Long,
        val ordering: OrderingDisclosure?
    )

    /** Performs the semantic, closed-set checks [parseEgressAttestation] deliberately does not
     * (mirroring [verifyDecision]'s parse/verify split): the binding must be in the closed set
     * (UnknownEgressBinding), and -- if present -- the field-6 ordering disclosure must satisfy its
     * basis-conditioned well-formedness rule (UnknownOrderingBasis/OrderingDisclosureMalformed). */
    fun validateEgressAttestation(a: EgressAttestation) {
        if (!isKnownBinding(a.binding)) {
            throw NaalpException(
                "UnknownEgressBinding",
                "egress attestation binding code is outside the closed set content_bound/content_free"
            )
        }
        a.ordering?.validate()
    }

    /**
     * Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
     * the signed object under the profile with real crypto against the GATEWAY's key; (2)
     * reconstructs it from the signed bytes; and (3) validates the binding code against the closed
     * set (UnknownEgressBinding), and the ordering disclosure if present. It takes NO serving-party
     * or connection identity: the authority is the signature over the bytes, so the same [obj] yields
     * an identical ResolvedEgressAttestation whether the gateway or an unrelated third party served
     * it (the third-party re-serve property). Any failure throws its named error and resolves nothing
     * (fail-closed).
     */
    fun verifyEgressAttestation(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ResolvedEgressAttestation {
        val parts = Cose.parseSign1Raw(obj)
        val halg = algFromProtected(parts[0])
        val (level, known) = Cose.algLevel(halg)
        if (!known) {
            throw NaalpException("UnknownAlg", "unregistered alg $halg")
        }
        if (level < Cose.profileMinLevel(profile)) {
            throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        }
        if (halg != alg) {
            throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        }
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) {
            throw NaalpException("BadSignature", "signature does not verify")
        }
        val a = parseEgressAttestation(parts[1])
        validateEgressAttestation(a)
        return ResolvedEgressAttestation(a.binding, a.digest.copyOf(), Policy.normalizeEffect(a.effect), a.audience.copyOf(), a.at, a.ordering)
    }

    // ---- content_free commitment open/verify pair -------------------------------------------------

    /** The content_free hiding commitment over an object's T1 content-id and a salt:
     * SHA-384(objectCid || salt) (48 octets). The commitment reveals nothing about objectCid without
     * the salt; a gateway builds it once to populate a content_free attestation's [digest] field, and
     * retains objectCid+salt to later prove which object crossed via [openEgressCommitment]. */
    fun egressCommit(objectCid: ByteArray, salt: ByteArray): ByteArray {
        val b = ByteArray(objectCid.size + salt.size)
        System.arraycopy(objectCid, 0, b, 0, objectCid.size)
        System.arraycopy(salt, 0, b, objectCid.size, salt.size)
        return sha384(b)
    }

    /** Proves which object crossed under a content_free attestation. It recomputes
     * egressCommit(objectCid, salt) and compares it, in constant time, against `a.digest`. Returns
     * true iff [a] is a content_free attestation AND the recomputed commitment matches: a wrong salt
     * or a wrong objectCid both fail to open (return false), and a content_bound attestation never
     * opens (its digest is not a commitment). */
    fun openEgressCommitment(a: EgressAttestation, objectCid: ByteArray, salt: ByteArray): Boolean {
        if (a.binding != BINDING_CONTENT_FREE) {
            return false
        }
        val want = egressCommit(objectCid, salt)
        if (want.size != a.digest.size) {
            return false
        }
        return MessageDigest.isEqual(want, a.digest)
    }
}
