// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest

/**
 * N-AALP C20 governed negotiation, advisory risk labels, and trust references for the Kotlin SDK
 * (design.md section 23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
 *
 * C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new envelope,
 * encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP
 * body (COSE_Sign1), reusing the closed C5 effect lattice (Policy), the T1 content-id framing, and the
 * causal partial order (the `causes` field) UNCHANGED.
 *
 * Governed negotiation: a Message {1: negotiation, 2: role, 3: profile, 4: causes[]} is one signed
 * step -- an OFFER, a COUNTER, or an ACCEPT. Steps are CAUSALLY LINKED by content-id in `causes`. Each
 * step SELECTS a profile from a CLOSED, PRE-REGISTERED set: the negotiation selects a pre-registered
 * profile, it never negotiates free-form runtime behavior. An ACCEPT MUST DESCEND from its offer
 * (walking the causes DAG reaches the offer's content-id), or it is rejected (NotDescended). An unknown
 * profile is rejected (UnknownProfile); an unknown role is rejected (UnknownRole).
 *
 * Advisory risk labels: a RiskLabel {1: code, 2: critical} is one carried advisory label; a
 * LabeledObject {1: effect, 2: labels[]} carries an effect together with a set of labels. The
 * critical-extension rule (R-2.5) applies: an unknown CRITICAL label is rejected; an unknown
 * NON-critical label is ignored. The LOAD-BEARING invariant: adding or carrying a risk label NEVER
 * changes an object's effect class -- [LabeledObject.effectClass] derives from the effect field ALONE,
 * so the closed C5 lattice is untouched. Risk labels are an advisory dimension, not a fifth effect.
 *
 * Trust references: a TrustRef {1: registry, 2: reference, 3: subject} carries a third-party trust
 * statement as a CHECKABLE signed object: `reference` is the T1 content-id of an external registry
 * record. [verifyTrustRef] confirms it by RECOMPUTING that content-id over the presented record. But
 * NO wire field WEIGHS the statement -- there is no score, rank, or ordering, and this module provides
 * NO scoring function. The protocol carries trust statements; it does not weigh them.
 *
 * An independent transcription of impl/go/negotiation (a second reference is
 * impl/python/naalp/negotiation.py), graded against the shared vectors/negotiation/cases.json. Kotlin
 * signs and verifies with real deterministic FIPS-204 ML-DSA-65 (BouncyCastle), so the signed objects
 * are byte-identical to the Go and Rust references (the three cross-language signed pins). Every check
 * is fail-closed: a failing object is rejected whole, throws its named error, and causes no state
 * change.
 */
object Negotiation {
    /** The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain. */
    const val HEAD_SIZE = 48

    // ==== governed negotiation ====================================================================

    /** The closed negotiation-message roles; a role outside the set is rejected (UnknownRole). */
    const val ROLE_OFFER = 0L   // the initiating offer (the root of a negotiation; no causes)
    const val ROLE_COUNTER = 1L // a counter-offer chaining onto the offer or a prior counter
    const val ROLE_ACCEPT = 2L  // the accept; it MUST descend from its offer

    private val ROLE_NAMES = mapOf(ROLE_OFFER to "offer", ROLE_COUNTER to "counter", ROLE_ACCEPT to "accept")

    /** Reports whether [r] is one of the three defined negotiation roles. */
    fun knownRole(r: Long): Boolean = ROLE_NAMES.containsKey(r)

    /** The role name, or "unknown" for an out-of-range code. */
    fun roleName(r: Long): String = ROLE_NAMES[r] ?: "unknown"

    /** The closed pre-registered negotiation profiles; a profile outside the set is rejected
     *  (UnknownProfile). A negotiation SELECTS a pre-registered profile; it never carries a free-form
     *  capability string or a runtime-generated handler. */
    const val PROFILE_BASELINE = 0L  // the baseline capability profile
    const val PROFILE_STREAMING = 1L // the native-streaming capability profile (C9)
    const val PROFILE_BATCH = 2L     // the batched-delivery capability profile

    private val PROFILE_NAMES = mapOf(PROFILE_BASELINE to "baseline", PROFILE_STREAMING to "streaming", PROFILE_BATCH to "batch")

    /** Reports whether [p] is one of the pre-registered profiles. */
    fun isRegisteredProfile(p: Long): Boolean = PROFILE_NAMES.containsKey(p)

    /** The profile name, or "unknown" for an unregistered code. */
    fun profileName(p: Long): String = PROFILE_NAMES[p] ?: "unknown"

    /**
     * One signed step of a governed negotiation: an offer, a counter, or an accept. It is CAUSALLY
     * LINKED to its predecessor(s) by content-id in [causes] (empty for an offer). It SELECTS a
     * pre-registered [profile].
     */
    class Message(negotiation: ByteArray, val role: Long, val profile: Long, causes: List<ByteArray>) {
        val negotiation: ByteArray = negotiation.copyOf()
        val causes: List<ByteArray> = causes.map { it.copyOf() }

        /** Deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(negotiation)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(role)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(profile)),
                    Cbor.Pair(Cbor.U(4), Cbor.A(causes.map { Cbor.B(it) }))
                )
            )
        )

        /** The Message's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The Message's T1 content-id (50 octets) -- the id a successor names in its causes. */
        fun id(): ByteArray = Cbor.contentId(bytes())
    }

    /**
     * Reconstruct a Message from its body bytes alone. It does NOT validate the role or profile against
     * the closed sets -- that is [verifyMessage]'s job -- so a message carrying an unknown role or
     * profile can be represented (and then rejected). Fail-closed: a non-canonical body, a non-map, or
     * an absent/wrong-typed field 1-4 throws NegMalformed.
     */
    fun parseMessage(b: ByteArray): Message {
        val m = decodeMap(b) ?: throw malformed()
        val neg = bstrField(m, 1)
        val role = uintField(m, 2)
        val prof = uintField(m, 3)
        val causesV = field(m, 4)
        if (neg == null || role == null || prof == null || causesV !is Cbor.A) throw malformed()
        val causes = ArrayList<ByteArray>(causesV.items.size)
        for (e in causesV.items) {
            if (e !is Cbor.B) throw malformed()
            causes.add(e.v)
        }
        return Message(neg, role, prof, causes)
    }

    /** Produce the tagged COSE_Sign1 object over the Message body. */
    fun signMessage(m: Message, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), m.bytes())

    /**
     * Verify the Message's full signature under the profile with real crypto, reconstruct it from the
     * signed body bytes, and validate it against the closed sets: the role MUST be offer/counter/accept
     * (UnknownRole) and the selected profile MUST be pre-registered (UnknownProfile). Fail-closed.
     */
    fun verifyMessage(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): Message {
        val payload = verifySigned(obj, profile, alg, pubkey)
        val m = parseMessage(payload)
        if (!knownRole(m.role)) throw NaalpException("UnknownRole", "negotiation message role is not offer/counter/accept")
        if (!isRegisteredProfile(m.profile)) {
            throw NaalpException("UnknownProfile", "negotiation selects a profile outside the closed pre-registered set")
        }
        return m
    }

    /** Build the content-id -> Message index the descent walk resolves predecessors through; the key
     *  is the hex form of the T1 content-id (Message.id()). */
    fun indexById(msgs: List<Message>): Map<String, Message> {
        val byId = HashMap<String, Message>(msgs.size)
        for (m in msgs) byId[Hex.encode(m.id())] = m
        return byId
    }

    /**
     * Reports whether [accept] reaches [offer] by following causes edges resolved through [byId]: a
     * real reachability walk over the causal DAG. A cause that cannot be resolved through byId cannot
     * extend the chain through it, so a forged causes pointer to an id the verifier never saw does not
     * manufacture descent. Fail-closed.
     */
    fun descends(accept: Message, offer: Message, byId: Map<String, Message>): Boolean {
        val target = Hex.encode(offer.id())
        val seen = HashSet<String>()
        val stack = ArrayDeque<ByteArray>()
        stack.addAll(accept.causes)
        while (stack.isNotEmpty()) {
            val id = stack.removeLast()
            val k = Hex.encode(id)
            if (k == target) return true
            if (!seen.add(k)) continue
            val pred = byId[k] ?: continue // an unresolved cause: the chain cannot be walked through it
            stack.addAll(pred.causes)
        }
        return false
    }

    /**
     * Check an accept against its offer over a set of verified messages, fail-closed: [offer] must be a
     * genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile); [accept] must be an
     * accept selecting a pre-registered profile (NotAccept / UnknownProfile); and the accept must
     * DESCEND from the offer (NotDescended). Returns the AGREED profile (the accept's selected profile).
     */
    fun verifyAccept(accept: Message, offer: Message, byId: Map<String, Message>): Long {
        if (offer.role != ROLE_OFFER) throw NaalpException("NotOffer", "the object presented as the offer is not an offer role")
        if (!isRegisteredProfile(offer.profile)) throw NaalpException("UnknownProfile", "offer selects an unregistered profile")
        if (accept.role != ROLE_ACCEPT) throw NaalpException("NotAccept", "the object presented as the accept is not an accept role")
        if (!isRegisteredProfile(accept.profile)) throw NaalpException("UnknownProfile", "accept selects an unregistered profile")
        if (!descends(accept, offer, byId)) throw NaalpException("NotDescended", "accept does not descend from its offer along the causes chain")
        return accept.profile
    }

    // ==== advisory risk labels ====================================================================

    /** A risk label's advisory registry class: informing (informational) or gating (a policy MAY
     *  require an additional gate). Distinct from the per-carriage critical flag. */
    const val CLASS_INFORMING = 0L
    const val CLASS_GATING = 1L

    private val RISK_CLASS_NAMES = mapOf(CLASS_INFORMING to "informing", CLASS_GATING to "gating")

    /** The class name ("gating"/"informing"), or "" for an out-of-range value. */
    fun riskClassName(c: Long): String = RISK_CLASS_NAMES[c] ?: ""

    /** The closed standard risk-label vocabulary codes. */
    const val RISK_SENSITIVE = 1L   // gating: the object touches sensitive material
    const val RISK_EGRESS = 2L      // gating: the object causes data egress
    const val RISK_REVERSIBLE = 3L  // informing: the object's effect is reversible

    /** The first code of the private/experimental extensible range: a code at or above it is not in
     *  the standard vocabulary (carried critical it is rejected R-2.5, carried non-critical ignored). */
    const val EXTENSIBLE_RANGE_START = 0x1000L

    private val RISK_VOCAB = mapOf(RISK_SENSITIVE to CLASS_GATING, RISK_EGRESS to CLASS_GATING, RISK_REVERSIBLE to CLASS_INFORMING)

    /** A code's vocabulary class, or -1 for an unregistered code. */
    fun riskClassOf(code: Long): Long = RISK_VOCAB[code] ?: -1L

    /** Reports whether [code] is in the closed standard vocabulary. */
    fun isRegisteredRisk(code: Long): Boolean = RISK_VOCAB.containsKey(code)

    /** Reports whether [code] lies in the private/experimental extensible range. */
    fun inExtensibleRange(code: Long): Boolean = code >= EXTENSIBLE_RANGE_START

    /** One advisory risk label carried on an object: [code] is the label code; [critical] is the
     *  per-carriage must-understand flag (1 = critical, 0 = advisory) -- the uint 1/0, no CBOR
     *  boolean. */
    class RiskLabel(val code: Long, val critical: Long) {
        /** Reports whether the label is carried critical (must-understand). */
        fun isCritical(): Boolean = critical == 1L

        /** The risk label's CBOR map {1: code, 2: critical}. */
        fun toMap(): Cbor.M = Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.U(code)), Cbor.Pair(Cbor.U(2), Cbor.U(critical))))

        /** The deterministic-CBOR encoding of the risk-label body. */
        fun bytes(): ByteArray = Cbor.encode(toMap())
    }

    /** Parse one risk-label map, rejecting a malformed shape (NegMalformed) or a critical flag outside
     *  {0,1} (MalformedCriticalFlag). Fail-closed. */
    private fun riskLabelFromValue(v: Cbor.Value): RiskLabel {
        if (v !is Cbor.M) throw malformed()
        val code = uintField(v, 1)
        val crit = uintField(v, 2)
        if (code == null || crit == null) throw malformed()
        if (crit > 1) throw criticalFlag()
        return RiskLabel(code, crit)
    }

    /**
     * Apply the critical-extension rule (R-2.5) to a set of carried risk labels: return the RECOGNIZED
     * (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL
     * label (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. It NEVER
     * inspects or returns an effect -- risk labels are an advisory dimension, never a fifth effect.
     */
    fun validateLabels(labels: List<RiskLabel>): List<RiskLabel> {
        val recognized = ArrayList<RiskLabel>(labels.size)
        for (l in labels) {
            if (l.critical > 1) throw criticalFlag()
            if (isRegisteredRisk(l.code)) {
                recognized.add(l)
                continue
            }
            if (l.isCritical()) throw NaalpException("UnknownCriticalRisk", "an unknown risk label carried critical is rejected (R-2.5)")
            // unknown non-critical: ignored (dropped from the recognized set)
        }
        return recognized
    }

    /**
     * A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels
     * (field 2). It exists to demonstrate -- provably, in isolation -- the load-bearing invariant that
     * carrying a risk label NEVER changes the object's effect class.
     */
    class LabeledObject(val effect: Long, labels: List<RiskLabel>) {
        val labels: List<RiskLabel> = labels.toList()

        /** Deterministic-CBOR encoding {1: effect, 2: labels[]}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.U(effect)),
                    Cbor.Pair(Cbor.U(2), Cbor.A(labels.map { it.toMap() }))
                )
            )
        )

        /** The LabeledObject's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The LabeledObject's T1 content-id (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())

        /**
         * The object's C5 effect class, derived from the effect field ALONE and normalized fail-closed
         * (unknown -> destructive). It DELIBERATELY does not consult the risk labels: a risk label is an
         * advisory dimension, never a fifth effect, so the closed lattice is untouched by any label the
         * object carries. This is the load-bearing C20 invariant.
         */
        fun effectClass(): Long = Policy.normalizeEffect(effect)

        /** Apply the critical-extension rule to the object's carried labels. */
        fun validateLabels(): List<RiskLabel> = Negotiation.validateLabels(labels)
    }

    /** Reconstruct a LabeledObject from its body bytes alone. Field 1 (effect) and field 2 (labels[])
     *  are mandatory; a malformed shape throws NegMalformed (a bad critical flag MalformedCriticalFlag). */
    fun parseLabeledObject(b: ByteArray): LabeledObject {
        val m = decodeMap(b) ?: throw malformed()
        val eff = uintField(m, 1)
        val labelsV = field(m, 2)
        if (eff == null || labelsV !is Cbor.A) throw malformed()
        val labels = labelsV.items.map { riskLabelFromValue(it) }
        return LabeledObject(eff, labels)
    }

    /** Produce the tagged COSE_Sign1 object over the LabeledObject body. */
    fun signLabeledObject(o: LabeledObject, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), o.bytes())

    /**
     * Verify the LabeledObject signature under the profile, reconstruct it, and apply the
     * critical-extension rule (an unknown critical label is rejected). Returns the object and its
     * recognized labels. The object's effectClass is unchanged by any label. Fail-closed.
     */
    fun verifyLabeledObject(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): kotlin.Pair<LabeledObject, List<RiskLabel>> {
        val payload = verifySigned(obj, profile, alg, pubkey)
        val o = parseLabeledObject(payload)
        return kotlin.Pair(o, validateLabels(o.labels))
    }

    // ==== trust references (checkable, never weighed) =============================================

    /**
     * A third-party trust statement as a CHECKABLE signed object. [registry] is an opaque
     * external-registry identifier; [reference] is the T1 content-id of the referenced external record;
     * [subject] is the opaque id the statement is about. The wire CARRIES the reference; NO field here
     * weighs it -- there is no score, rank, or ordering.
     */
    class TrustRef(registry: ByteArray, reference: ByteArray, subject: ByteArray) {
        val registry: ByteArray = registry.copyOf()
        val reference: ByteArray = reference.copyOf()
        val subject: ByteArray = subject.copyOf()

        /** Deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(registry)),
                    Cbor.Pair(Cbor.U(2), Cbor.B(reference)),
                    Cbor.Pair(Cbor.U(3), Cbor.B(subject))
                )
            )
        )

        /** The TrustRef's SHA-384 head (48 octets). */
        fun head(): ByteArray = sha384(bytes())

        /** The TrustRef's own T1 content-id (50 octets). */
        fun id(): ByteArray = Cbor.contentId(bytes())

        /** The content-id the trust ref binds (the carried external-record reference). */
        fun referenceId(): ByteArray = reference.copyOf()

        /**
         * Reports whether the carried [reference] is the T1 content-id of [record] -- i.e. the
         * reference recomputes over the presented external bytes. This is the CHECK a relying party
         * runs; it computes NO score. A changed record yields a different content-id, so this returns
         * false.
         */
        fun bindsRecord(record: ByteArray): Boolean = reference.contentEquals(Cbor.contentId(record))
    }

    /** A TrustRef that has passed signature verification and (given the external record) the content-id
     *  recompute. It carries NO score, rank, or trust weight. */
    class ResolvedTrustRef(val registry: ByteArray, val reference: ByteArray, val subject: ByteArray)

    /** Reconstruct a TrustRef from its body bytes alone; fields 1-3 (all bstr) are mandatory. */
    fun parseTrustRef(b: ByteArray): TrustRef {
        val m = decodeMap(b) ?: throw malformed()
        val reg = bstrField(m, 1)
        val ref = bstrField(m, 2)
        val subj = bstrField(m, 3)
        if (reg == null || ref == null || subj == null) throw malformed()
        return TrustRef(reg, ref, subj)
    }

    /** Produce the tagged COSE_Sign1 object over the TrustRef body. */
    fun signTrustRef(r: TrustRef, alg: Int, seed: ByteArray): ByteArray =
        Cose.coseSign1(alg, seed, protectedHeader(alg), r.bytes())

    /**
     * Verify a trust reference end-to-end: verify the signed object under the profile with real crypto;
     * reconstruct it; and confirm the reference by RECOMPUTING the external record's content-id and
     * requiring it to equal the carried reference (ReferenceMismatch otherwise). Returns the resolved
     * reference -- and NOTHING that scores it. Fail-closed.
     */
    fun verifyTrustRef(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray, externalRecord: ByteArray): ResolvedTrustRef {
        val payload = verifySigned(obj, profile, alg, pubkey)
        val r = parseTrustRef(payload)
        if (!r.bindsRecord(externalRecord)) {
            throw NaalpException("ReferenceMismatch", "trust-ref reference content-id does not recompute over the presented external record")
        }
        return ResolvedTrustRef(r.registry, r.reference, r.subject)
    }

    // ---- shared crypto + small deterministic-CBOR helpers ----------------------------------------

    private fun malformed(): NaalpException =
        NaalpException("NegMalformed", "object is not a well-formed N-AALP negotiation/risk-label/labeled-object/trust-ref body")

    private fun criticalFlag(): NaalpException =
        NaalpException("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}: the spine carries no CBOR boolean, so it is rejected, never defaulted")

    private fun sha384(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-384").digest(b)

    /** The bare {1: alg} COSE_Sign1 protected header (as the reference's cose.Sign1 emits). */
    private fun protectedHeader(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    private fun algFromProtected(prot: ByteArray): Int {
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) throw malformed()
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L) {
                val value = p.v
                if (value is Cbor.N) return value.v.toInt()
                if (value is Cbor.U) return value.v.toInt()
            }
        }
        throw malformed()
    }

    /** Verify a signed C20 object end-to-end (signature, alg registry, profile floor) against [pubkey]
     *  and return the signed payload bytes. Any failure throws its named error (fail-closed). */
    private fun verifySigned(obj: ByteArray, profile: Long, alg: Int, pubkey: ByteArray): ByteArray {
        val parts = Cose.parseSign1Raw(obj) // [protected, payload, signature]
        val halg = algFromProtected(parts[0])
        val (level, known) = Cose.algLevel(halg)
        if (!known) throw NaalpException("UnknownAlg", "unregistered alg $halg")
        if (level < Cose.profileMinLevel(profile)) throw NaalpException("ProfileDowngrade", "signature level below the profile minimum")
        if (halg != alg) throw NaalpException("KeyAlgMismatch", "alg $halg does not match the verifier key alg $alg")
        val tbs = Cose.toBeSignedRaw(parts[0], parts[1])
        if (!Cose.coseVerify1Raw(halg, pubkey, tbs, parts[2])) throw NaalpException("BadSignature", "signature does not verify")
        return parts[1]
    }

    private fun decodeMap(b: ByteArray): Cbor.M? {
        val v = try {
            Cbor.decode(b)
        } catch (e: NaalpException) {
            return null
        }
        return v as? Cbor.M
    }

    private fun field(m: Cbor.M, k: Long): Cbor.Value? {
        for (p in m.pairs) {
            val key = p.k
            if (key is Cbor.U && key.v == k) return p.v
        }
        return null
    }

    private fun uintField(m: Cbor.M, k: Long): Long? = (field(m, k) as? Cbor.U)?.v

    private fun bstrField(m: Cbor.M, k: Long): ByteArray? = (field(m, k) as? Cbor.B)?.v
}
