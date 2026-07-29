// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
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
