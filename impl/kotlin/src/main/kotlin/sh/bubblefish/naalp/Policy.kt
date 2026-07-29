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
}
