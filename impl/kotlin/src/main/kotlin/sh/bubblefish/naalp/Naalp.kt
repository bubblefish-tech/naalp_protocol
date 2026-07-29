// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * A rejection raised by an N-AALP construction when an input violates a normative rule
 * (non-canonical CBOR, non-NFC identity, unknown alg, causal violation, unknown channel/kind,
 * effect-declaration mismatch, unknown transport, undefined carriage class). The [kind] field
 * names the rule, mirroring the Python/Java reference error kinds. The conformance adapter turns
 * any NaalpException into a wire `{"error": ...}` response — which is exactly what a MUST-reject
 * (`result:"invalid"`) corpus case requires.
 */
class NaalpException(val kind: String, detail: String) : RuntimeException("$kind: $detail")

/** The full N-AALP object type, re-exported at the package root for ergonomics. */
typealias NaalpObject = Envelope.Object

/**
 * The ergonomic high-level entry point to the N-AALP Kotlin SDK. It re-exports the algorithm and
 * profile constants and the object [sign]/[verify] surface, so a caller can work entirely through
 * `Naalp.*` without importing the individual C-layer objects ([Cbor], [Cose], [Identity], [Policy],
 * [Records], [Graph], [Channels], [Envelope]) — though all remain public for direct use.
 *
 * Example:
 * ```
 * val seed = ByteArray(32) { 0x2a }
 * val pk   = Cose.mldsaKeygen("ML-DSA-65", seed)
 * val sid  = Identity.signerId(Naalp.ALG_MLDSA65, pk)
 * val obj  = NaalpObject(kind = 1, channel = 4, signer = sid.toByteArray(),
 *                        created = 1785000000000L, effect = 2, profile = Naalp.PROFILE_PUBLIC,
 *                        body = Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.T("hello")))))
 * val signed = Naalp.sign(obj, Naalp.ALG_MLDSA65, seed)
 * val got    = Naalp.verify(Naalp.PROFILE_PUBLIC, Naalp.ALG_MLDSA65, pk, { c, k -> c == 4L && k == 1L }, signed)
 * ```
 */
object Naalp {
    const val VERSION = "0.1.0"

    const val ALG_MLDSA65 = Cose.ALG_MLDSA65
    const val ALG_MLDSA87 = Cose.ALG_MLDSA87
    const val ALG_ED25519 = Cose.ALG_ED25519

    const val PROFILE_PUBLIC = Cose.PROFILE_PUBLIC
    const val PROFILE_ENTERPRISE = Cose.PROFILE_ENTERPRISE
    const val PROFILE_SOVEREIGN = Cose.PROFILE_SOVEREIGN

    /** Content-id-bind and deterministically sign a full N-AALP object; see [Envelope.sign]. */
    fun sign(obj: NaalpObject, alg: Int, seed: ByteArray): ByteArray = Envelope.sign(obj, alg, seed)

    /** Offline-verify a signed N-AALP object end-to-end; see [Envelope.verify]. */
    fun verify(
        profile: Long,
        alg: Int,
        pubkey: ByteArray,
        kindValidator: Envelope.KindValidator?,
        objBytes: ByteArray,
        knownCext: Set<Long> = emptySet(),
    ): NaalpObject = Envelope.verify(profile, alg, pubkey, kindValidator, objBytes, knownCext)
}

/** Lowercase-hex encode/decode for the byte-valued wire fields of the conformance protocol. */
object Hex {
    private val DIGITS = "0123456789abcdef".toCharArray()

    fun encode(b: ByteArray): String {
        val out = CharArray(b.size * 2)
        for (i in b.indices) {
            val v = b[i].toInt() and 0xFF
            out[2 * i] = DIGITS[v ushr 4]
            out[2 * i + 1] = DIGITS[v and 0x0F]
        }
        return String(out)
    }

    fun decode(s: String): ByteArray {
        if ((s.length and 1) != 0) {
            throw NaalpException("Malformed", "odd-length hex string")
        }
        val n = s.length / 2
        val b = ByteArray(n)
        for (i in 0 until n) {
            val hi = Character.digit(s[2 * i], 16)
            val lo = Character.digit(s[2 * i + 1], 16)
            if (hi < 0 || lo < 0) {
                throw NaalpException("Malformed", "invalid hex digit")
            }
            b[i] = ((hi shl 4) or lo).toByte()
        }
        return b
    }
}
