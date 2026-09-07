// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * N-AALP C5 effect vocabulary and authorization for the Kotlin SDK (§6).
 *
 * The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an unrecognized
 * value fails closed to destructive (R-6.2); authorization is the §6.1 lattice (action <= ceiling).
 * The optional signed safety label is a CBOR map {1:risk, 2:scope}.
 */
object Policy {
    const val READ_ONLY = 0L
    const val IDEMPOTENT_WRITE = 1L
    const val NON_IDEMPOTENT_WRITE = 2L
    const val DESTRUCTIVE = 3L

    /** Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2). */
    fun normalizeEffect(v: Long): Long = if (v in 0..3) v else DESTRUCTIVE

    /** The §6.1 lattice: an action is permitted under ceiling iff action <= ceiling. */
    fun authorizes(ceiling: Long, action: Long): Boolean = action <= ceiling

    /** The signed safety-label body {1: risk, 2: scope} (R-6.4). */
    fun safetyLabelBytes(risk: String, scope: String): ByteArray =
        Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.T(risk)),
                    Cbor.Pair(Cbor.U(2), Cbor.T(scope))
                )
            )
        )

    /** Where a claimed identity came from; only a signature-derived identity is an authorization
     * principal (R-6.5). */
    enum class PrincipalSource {
        SIGNATURE,          // the verified COSE signature's signer id
        TRANSPORT_METADATA, // e.g. a TLS peer name / connection tag
        FOREIGN_HEADER,     // e.g. an X-Agent-ID or a carried foreign header
        CLIENT_NAME,        // e.g. a self-asserted clientInfo.name
    }

    /** Return the authorization principal id iff it is signature-derived and non-empty (R-6.5); a
     * transport-metadata, foreign-header, or client-supplied name is refused UnauthenticatedPrincipal —
     * it is never treated as an authorization identity. */
    fun resolveAuthPrincipal(src: PrincipalSource, id: String): String {
        if (src != PrincipalSource.SIGNATURE || id.isEmpty()) {
            throw NaalpException(
                "UnauthenticatedPrincipal",
                "an authorization identity must be signature-derived, not transport/foreign/client-asserted"
            )
        }
        return id
    }

    /** The non-critical ext key under which the optional safety label is carried (design §6.4). */
    const val SAFETY_LABEL_EXT_KEY = 1L

    /** The OPTIONAL signed safety annotation (R-6.4): an accountable, attributable claim, not a
     * guarantee the content is safe. */
    data class SafetyLabel(val risk: String, val scope: String)

    /** Extract the optional safety label from an object's ext map: (label, true) when a well-formed
     * label is present, (null, false) when absent, and throws MalformedSafetyLabel when the ext[1]
     * entry is present but not exactly {1:tstr, 2:tstr} — rejected, never silently accepted. */
    fun safetyLabelFromExt(ext: Cbor.M): kotlin.Pair<SafetyLabel?, Boolean> {
        for (p in ext.pairs) {
            val k = p.k
            if (k !is Cbor.U || k.v != SAFETY_LABEL_EXT_KEY) continue
            val inner = p.v as? Cbor.M
                ?: throw NaalpException("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
            var risk: String? = null
            var scope: String? = null
            for (q in inner.pairs) {
                val kk = q.k as? Cbor.U
                val vv = q.v as? Cbor.T
                if (kk == null || vv == null) {
                    throw NaalpException("MalformedSafetyLabel", "safety label entry is not {uint: tstr}")
                }
                when (kk.v) {
                    1L -> risk = vv.v
                    2L -> scope = vv.v
                }
            }
            val r = risk ?: throw NaalpException("MalformedSafetyLabel", "safety label missing risk")
            val s = scope ?: throw NaalpException("MalformedSafetyLabel", "safety label missing scope")
            return kotlin.Pair(SafetyLabel(r, s), true)
        }
        return kotlin.Pair(null, false)
    }

    /** A capability an endpoint issues to an authenticated signer id: the most dangerous effect that
     * principal is permitted to carry. The zero maxEffect (READ_ONLY) is the least-privilege default. */
    class Grant(val principal: String, val maxEffect: Long) {
        /** The endpoint policy check making the effect an authorization input, not a hint (R-6.3):
         * resolve the presenter (refusing any non-signature source, R-6.5), require it to match this
         * grant's principal, and deny an object effect exceeding the ceiling (normalized fail-closed,
         * R-6.2). No side effect; throws on any failure. */
        fun authorizeObject(src: PrincipalSource, presented: String, objectEffect: Long) {
            val who = resolveAuthPrincipal(src, presented)
            if (who != principal) {
                throw NaalpException("EffectNotAuthorized", "object effect exceeds the granted capability")
            }
            if (!authorizes(maxEffect, normalizeEffect(objectEffect))) {
                throw NaalpException("EffectNotAuthorized", "object effect exceeds the granted capability")
            }
        }
    }
}
