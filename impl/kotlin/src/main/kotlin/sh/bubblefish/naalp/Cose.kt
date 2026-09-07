// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.security.MessageDigest
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithContext
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.MLDSASigner

/**
 * N-AALP C2 signing layer for the Kotlin SDK: the COSE_Sign1 (RFC 9052) signing-input and object
 * assembly, plus deterministic ML-DSA (FIPS 204, rnd=0) and Ed25519 (RFC 8032).
 *
 * The deterministic ML-DSA path uses Bouncy Castle's [MLDSASigner] initialised WITHOUT a
 * ParametersWithRandom, so the FIPS 204 `rnd` stays 32 zero bytes — byte-identical to the Go
 * (CIRCL), Rust (fips204), Python (dilithium-py) and Java (Bouncy Castle) reference implementations.
 * Key material is derived from the 32-byte NIST seed (xi) via the seed-only private-key constructor,
 * so the public key equals the NIST ACVP keyGen vector.
 */
object Cose {
    const val ALG_MLDSA65 = -49
    const val ALG_MLDSA87 = -50
    const val ALG_ED25519 = -19

    const val PROFILE_PUBLIC = 1L
    const val PROFILE_ENTERPRISE = 2L
    const val PROFILE_SOVEREIGN = 3L

    const val TAG_SIGN1 = 18L

    /**
     * NIST security level of a registered alg, paired with whether it is registered. ML-DSA-87 is
     * level 5, ML-DSA-65 is level 3, Ed25519 is classical (level 0, valid only as a hybrid leg);
     * any other alg is unregistered. Mirrors the Go/Rust/Python C2 registry.
     */
    fun algLevel(alg: Int): kotlin.Pair<Int, Boolean> = when (alg) {
        ALG_MLDSA87 -> kotlin.Pair(5, true)
        ALG_MLDSA65 -> kotlin.Pair(3, true)
        ALG_ED25519 -> kotlin.Pair(0, true)
        else -> kotlin.Pair(0, false)
    }

    /** Minimum signature level a profile accepts (Sovereign floors at level 5; else level 3). */
    fun profileMinLevel(profile: Long): Int = if (profile == PROFILE_SOVEREIGN) 5 else 3

    /** The RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header. */
    fun toBeSignedRaw(protectedHeader: ByteArray, payload: ByteArray): ByteArray =
        Cbor.encode(
            Cbor.A(
                listOf(
                    Cbor.T("Signature1"),
                    Cbor.B(protectedHeader),
                    Cbor.B(ByteArray(0)),
                    Cbor.B(payload)
                )
            )
        )

    /** The tagged COSE_Sign1 object: 18([protected, {}, payload, signature]). */
    fun assembleSign1Raw(protectedHeader: ByteArray, payload: ByteArray, sig: ByteArray): ByteArray =
        Cbor.encode(
            Cbor.Tag(
                TAG_SIGN1,
                Cbor.A(
                    listOf(
                        Cbor.B(protectedHeader),
                        Cbor.M(listOf()),
                        Cbor.B(payload),
                        Cbor.B(sig)
                    )
                )
            )
        )

    /** Recover [protected, payload, sig] from a tagged COSE_Sign1 object. */
    fun parseSign1Raw(obj: ByteArray): Array<ByteArray> {
        val v = Cbor.decode(obj)
        if (v !is Cbor.Tag || v.n != TAG_SIGN1 || v.content !is Cbor.A) {
            throw NaalpException("Malformed", "not a tagged COSE_Sign1")
        }
        val items = v.content.items
        if (items.size != 4 || items[0] !is Cbor.B || items[2] !is Cbor.B || items[3] !is Cbor.B) {
            throw NaalpException("Malformed", "malformed COSE_Sign1 array")
        }
        return arrayOf((items[0] as Cbor.B).v, (items[2] as Cbor.B).v, (items[3] as Cbor.B).v)
    }

    // --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

    const val TAG_SIGN = 98L

    /** A parsed tag-98 COSE_Sign: body protected header, payload, and ordered [sprot, sig] legs. */
    class RotationParse(val bodyProt: ByteArray, val payload: ByteArray, val legs: List<Array<ByteArray>>)

    /** One COSE_Signature protected header: {1: alg} (RFC 9052 §4). */
    fun legProtected(alg: Int): ByteArray =
        Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.N(alg.toLong())))))

    /**
     * The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
     * det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). Note the
     * five-element "Signature" structure (with the per-leg sign_protected) vs the four-element
     * "Signature1" of a COSE_Sign1.
     */
    fun signatureToBeSigned(bodyProt: ByteArray, signerAlg: Int, payload: ByteArray): ByteArray =
        Cbor.encode(
            Cbor.A(
                listOf(
                    Cbor.T("Signature"),
                    Cbor.B(bodyProt),
                    Cbor.B(legProtected(signerAlg)),
                    Cbor.B(ByteArray(0)),
                    Cbor.B(payload)
                )
            )
        )

    /** Build one COSE_Signature leg: [leg_protected_bytes, signature_bytes]. */
    fun signatureLeg(bodyProt: ByteArray, alg: Int, seed: ByteArray, payload: ByteArray): Array<ByteArray> {
        val sprot = legProtected(alg)
        val sig = mldsaSign(alg, seed, signatureToBeSigned(bodyProt, alg, payload))
        return arrayOf(sprot, sig)
    }

    /** The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]). */
    fun assembleSignRaw(bodyProt: ByteArray, payload: ByteArray, legs: List<Array<ByteArray>>): ByteArray {
        val sigArr = legs.map { leg -> Cbor.A(listOf(Cbor.B(leg[0]), Cbor.M(listOf()), Cbor.B(leg[1]))) }
        return Cbor.encode(
            Cbor.Tag(
                TAG_SIGN,
                Cbor.A(listOf(Cbor.B(bodyProt), Cbor.M(listOf()), Cbor.B(payload), Cbor.A(sigArr)))
            )
        )
    }

    /** Recover the body protected header, payload, and ordered legs from a tagged COSE_Sign object. */
    fun parseSignRaw(obj: ByteArray): RotationParse {
        val v = Cbor.decode(obj)
        if (v !is Cbor.Tag || v.n != TAG_SIGN || v.content !is Cbor.A) {
            throw NaalpException("Malformed", "not a tagged COSE_Sign")
        }
        val items = v.content.items
        if (items.size != 4 || items[0] !is Cbor.B || items[2] !is Cbor.B || items[3] !is Cbor.A) {
            throw NaalpException("Malformed", "malformed COSE_Sign array")
        }
        val legs = ArrayList<Array<ByteArray>>()
        for (sv in (items[3] as Cbor.A).items) {
            if (sv !is Cbor.A || sv.items.size != 3 || sv.items[0] !is Cbor.B || sv.items[2] !is Cbor.B) {
                throw NaalpException("Malformed", "malformed COSE_Signature leg")
            }
            legs.add(arrayOf((sv.items[0] as Cbor.B).v, (sv.items[2] as Cbor.B).v))
        }
        return RotationParse((items[0] as Cbor.B).v, (items[2] as Cbor.B).v, legs)
    }

    /** Extract the alg (label 1) value from a serialized leg protected header {1: alg}. */
    fun algFromProtected(prot: ByteArray): Int {
        // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
        // wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
        // before interpreting the header — the empty protected header is pinned to 0x40.
        if (prot.size == 1 && (prot[0].toInt() and 0xFF) == 0xA0) {
            throw NaalpException("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)")
        }
        val v = Cbor.decode(prot)
        if (v !is Cbor.M) throw NaalpException("Malformed", "protected header not a map")
        for (p in v.pairs) {
            val k = p.k
            if (k is Cbor.U && k.v == 1L && p.v is Cbor.N) return (p.v as Cbor.N).v.toInt()
        }
        throw NaalpException("Malformed", "no alg in protected header")
    }

    // --- ML-DSA (FIPS 204) ---

    private fun mldsaParams(alg: Int): MLDSAParameters = when (alg) {
        ALG_MLDSA65 -> MLDSAParameters.ml_dsa_65
        ALG_MLDSA87 -> MLDSAParameters.ml_dsa_87
        else -> throw NaalpException("UnknownAlg", "alg $alg is not an ML-DSA algorithm")
    }

    /** Derive the public key from a 32-byte seed (NIST ACVP keyGen); returns pk bytes. */
    fun mldsaKeygen(param: String, seed: ByteArray): ByteArray {
        val p = if (param == "ML-DSA-87") MLDSAParameters.ml_dsa_87 else MLDSAParameters.ml_dsa_65
        if (seed.size != 32) throw NaalpException("Malformed", "ML-DSA seed must be 32 bytes")
        val sk = MLDSAPrivateKeyParameters(p, seed)
        return sk.publicKey
    }

    /** Deterministic (rnd=0) ML-DSA signature over tbs with the key derived from seed. */
    fun mldsaSign(alg: Int, seed: ByteArray, tbs: ByteArray): ByteArray {
        val p = mldsaParams(alg)
        if (seed.size != 32) throw NaalpException("Malformed", "ML-DSA seed must be 32 bytes")
        val sk = MLDSAPrivateKeyParameters(p, seed)
        val signer = MLDSASigner()
        signer.init(true, sk) // no ParametersWithRandom -> rnd = 32 zero bytes (deterministic)
        signer.update(tbs, 0, tbs.size)
        return try {
            signer.generateSignature()
        } catch (e: Exception) {
            throw NaalpException("SignFailed", e.toString())
        }
    }

    fun mldsaVerify(alg: Int, pk: ByteArray, tbs: ByteArray, sig: ByteArray): Boolean {
        val p = mldsaParams(alg)
        val pub = MLDSAPublicKeyParameters(p, pk)
        val signer = MLDSASigner()
        signer.init(false, pub)
        signer.update(tbs, 0, tbs.size)
        return signer.verifySignature(sig)
    }

    // --- Ed25519 (RFC 8032) ---

    fun ed25519Sign(seed: ByteArray, msg: ByteArray): ByteArray {
        if (seed.size != 32) throw NaalpException("Malformed", "ed25519 secret key must be a 32-byte seed")
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    fun ed25519Verify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pk.size != 32) return false
        val pub = Ed25519PublicKeyParameters(pk, 0)
        val signer = Ed25519Signer()
        signer.init(false, pub)
        signer.update(msg, 0, msg.size)
        return signer.verifySignature(sig)
    }

    // --- LAMPS opt-in composite signature (alg -65537, design.md §4.2) ---

    const val ALG_COMPOSITE_65_ED25519 = -65537 // COMPSIG-MLDSA65-Ed25519-SHA512
    const val ALG_COMPOSITE_44_ED25519 = -65538 // edge; RESERVED, not implemented
    private val COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025".toByteArray(Charsets.US_ASCII)
    private val COMPOSITE_LABEL_MLDSA65_ED25519 = "COMPSIG-MLDSA65-Ed25519-SHA512".toByteArray(Charsets.US_ASCII)
    private const val MLDSA65_SIG_SIZE = 3309 // FIPS 204 ML-DSA-65 signature size
    const val MLDSA65_PUB_SIZE = 1952 // FIPS 204 ML-DSA-65 pubkey size (composite split point)

    /**
     * The LAMPS composite message representative M' = Prefix || Label || len(ctx) || ctx ||
     * SHA-512(M) (design.md §4.2). len(ctx) is a single length octet; the N-AALP composite context
     * is empty, so the octet is 0x00. Both legs sign this same M'.
     */
    fun computeMprime(label: ByteArray, ctx: ByteArray, m: ByteArray): ByteArray {
        if (ctx.size > 255) throw NaalpException("Malformed", "composite context exceeds one length octet")
        val h = MessageDigest.getInstance("SHA-512").digest(m)
        val out = ByteArray(COMPOSITE_PREFIX.size + label.size + 1 + ctx.size + h.size)
        var o = 0
        COMPOSITE_PREFIX.copyInto(out, o); o += COMPOSITE_PREFIX.size
        label.copyInto(out, o); o += label.size
        out[o++] = ctx.size.toByte() // len(ctx) as a single length octet
        ctx.copyInto(out, o); o += ctx.size
        h.copyInto(out, o)
        return out
    }

    /**
     * The LAMPS composite signature value over the COSE ToBeSigned tbs: mldsaSig || tradSig
     * (ML-DSA-65 first, raw concatenation; §4.2). The ML-DSA leg is deterministic (no
     * ParametersWithRandom => rnd=0) with context = the suite Label octets (via ParametersWithContext);
     * the Ed25519 leg signs M' with no context.
     */
    fun compositeSign(mldsaSeed: ByteArray, edSeed: ByteArray, tbs: ByteArray): ByteArray {
        if (mldsaSeed.size != 32) throw NaalpException("Malformed", "ML-DSA seed must be 32 bytes")
        val mprime = computeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, ByteArray(0), tbs)
        val sk = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, mldsaSeed)
        val signer = MLDSASigner()
        signer.init(true, ParametersWithContext(sk, COMPOSITE_LABEL_MLDSA65_ED25519))
        signer.update(mprime, 0, mprime.size)
        val mldsaSig = try {
            signer.generateSignature()
        } catch (e: Exception) {
            throw NaalpException("SignFailed", e.toString())
        }
        val tradSig = ed25519Sign(edSeed, mprime)
        return mldsaSig + tradSig // ML-DSA first (LAMPS order)
    }

    /**
     * Valid IFF BOTH the ML-DSA-65 leg (context = Label) and the Ed25519 leg (no context) validate
     * over M'. A value of the wrong length is malformed and rejected. A stripped or re-interpreted
     * lone leg has no valid composite because M' binds both components (RFC 9955; §4.2/§4.5).
     */
    fun compositeVerify(mldsaPk: ByteArray, edPk: ByteArray, m: ByteArray, sig: ByteArray): Boolean {
        if (sig.size != MLDSA65_SIG_SIZE + 64) return false
        val mprime = computeMprime(COMPOSITE_LABEL_MLDSA65_ED25519, ByteArray(0), m)
        val pub = MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, mldsaPk)
        val signer = MLDSASigner()
        signer.init(false, ParametersWithContext(pub, COMPOSITE_LABEL_MLDSA65_ED25519))
        signer.update(mprime, 0, mprime.size)
        val mldsaOk = signer.verifySignature(sig.copyOfRange(0, MLDSA65_SIG_SIZE))
        val edOk = ed25519Verify(edPk, mprime, sig.copyOfRange(MLDSA65_SIG_SIZE, sig.size))
        return mldsaOk && edOk
    }

    /** Produce a deterministic tagged COSE_Sign1 object over (protected, payload). */
    fun coseSign1(alg: Int, seed: ByteArray, protectedHeader: ByteArray, payload: ByteArray): ByteArray {
        val tbs = toBeSignedRaw(protectedHeader, payload)
        val sig = mldsaSign(alg, seed, tbs)
        return assembleSign1Raw(protectedHeader, payload, sig)
    }

    /** Verify a raw signature over already-assembled ToBeSigned bytes, dispatching by alg. */
    fun coseVerify1Raw(alg: Int, pk: ByteArray, tbs: ByteArray, sig: ByteArray): Boolean = when (alg) {
        ALG_MLDSA65, ALG_MLDSA87 -> mldsaVerify(alg, pk, tbs, sig)
        ALG_ED25519 -> ed25519Verify(pk, tbs, sig)
        else -> throw NaalpException("UnknownAlg", "unknown alg $alg")
    }

    fun coseVerify1(alg: Int, pk: ByteArray, obj: ByteArray): Boolean {
        val parts = parseSign1Raw(obj)
        val tbs = toBeSignedRaw(parts[0], parts[1])
        return coseVerify1Raw(alg, pk, tbs, parts[2])
    }
}
