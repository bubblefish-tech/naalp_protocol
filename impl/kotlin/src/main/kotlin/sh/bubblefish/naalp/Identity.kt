// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.text.Normalizer

/**
 * N-AALP C4 identity for the Kotlin SDK: the self-certifying signer id (§5.1) and the NFC rule.
 *
 * signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
 * identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats registry:
 * ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12. The multibase
 * prefix is 'b' (base32 lowercase, no padding).
 */
object Identity {
    private const val MH_SHA256 = 0x12
    private val B32 = "abcdefghijklmnopqrstuvwxyz234567".toCharArray()

    private fun multicodec(alg: Int): Int = when (alg) {
        Cose.ALG_ED25519 -> 0xED
        Cose.ALG_MLDSA65 -> 0x1211
        Cose.ALG_MLDSA87 -> 0x1212
        else -> throw NaalpException("UnknownAlg", "no multicodec for alg $alg")
    }

    /** LEB128 unsigned varint. */
    fun uvarint(n: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var v = n.toLong() and 0xFFFFFFFFL
        while (true) {
            val b = (v and 0x7F).toInt()
            v = v ushr 7
            if (v != 0L) {
                out.write(b or 0x80)
            } else {
                out.write(b)
                break
            }
        }
        return out.toByteArray()
    }

    private fun sha256(): MessageDigest = MessageDigest.getInstance("SHA-256")

    /** Base32 (RFC 4648) lowercase, no padding. */
    fun base32NoPad(data: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                sb.append(B32[(buffer ushr bits) and 0x1F])
            }
        }
        if (bits > 0) {
            sb.append(B32[(buffer shl (5 - bits)) and 0x1F])
        }
        return sb.toString()
    }

    /** The self-certifying signer id for (alg, pubkey). */
    fun signerId(alg: Int, pubkey: ByteArray): String {
        val mc = multicodec(alg)
        val mcv = uvarint(mc)
        val tagged = ByteArray(mcv.size + pubkey.size)
        System.arraycopy(mcv, 0, tagged, 0, mcv.size)
        System.arraycopy(pubkey, 0, tagged, mcv.size, pubkey.size)
        val digest = sha256().digest(tagged)
        val mhCode = uvarint(MH_SHA256)
        val mhLen = uvarint(digest.size)
        val mh = ByteArray(mhCode.size + mhLen.size + digest.size)
        System.arraycopy(mhCode, 0, mh, 0, mhCode.size)
        System.arraycopy(mhLen, 0, mh, mhCode.size, mhLen.size)
        System.arraycopy(digest, 0, mh, mhCode.size + mhLen.size, digest.size)
        return "b" + base32NoPad(mh)
    }

    /**
     * The self-certifying signer id for a composite key pair (§5.1). The SHA-256 preimage is the
     * multicodec-tagged ML-DSA public key concatenated with the multicodec-tagged Ed25519 public key
     * — using only existing official multicodecs (no minted code) — so stripping or substituting
     * either leg changes the id (=> SignerMismatch before verify). Downgrade-resistant.
     */
    fun compositeSignerId(mldsaAlg: Int, mldsaPub: ByteArray, edPub: ByteArray): String {
        if (mldsaAlg != Cose.ALG_MLDSA65 && mldsaAlg != Cose.ALG_MLDSA87) {
            throw NaalpException("UnknownAlg", "composite signer id requires an ML-DSA alg, got $mldsaAlg")
        }
        val preimage = uvarint(multicodec(mldsaAlg)) + mldsaPub + uvarint(multicodec(Cose.ALG_ED25519)) + edPub
        val digest = sha256().digest(preimage)
        val mh = uvarint(MH_SHA256) + uvarint(digest.size) + digest
        return "b" + base32NoPad(mh)
    }

    fun checkSigner(claimed: String, alg: Int, pubkey: ByteArray) {
        if (signerId(alg, pubkey) != claimed) {
            throw NaalpException("SignerMismatch", "signer id does not recompute from the key")
        }
    }

    /** Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3). */
    fun requireNfc(s: String) {
        if (Normalizer.normalize(s, Normalizer.Form.NFC) != s) {
            throw NaalpException("NonNFC", "string is not Unicode NFC")
        }
    }

    /** Decode a UTF-8 byte payload to a String (matches the adapter's utf8_hex handling). */
    fun utf8(b: ByteArray): String = String(b, Charsets.UTF_8)

    // ---- key lifecycle: co-signed identity rotation (design.md 5.2; R-5.2, R-5.5) --------
    //
    // ADDED ADDITIVELY (Wave D, feature #64 rooms) - the C4 identity-rotation primitive the room
    // rebind path (Rooms.PrincipalRegistry.rebind, R-1.4) composes on, placed here on the identity
    // spine where the Go reference (impl/go/identity) puts it, NOT duplicated inside Rooms. Mirrors
    // impl/python/naalp/identity + impl/java (RotationRecord / signRotation / verifyRotation /
    // RotationUnauthorized). New members only; nothing above is changed.

    /**
     * Links an old signer id to a new one from [notBefore] (5.2). Its signed bytes are the
     * deterministic-CBOR map {1:old, 2:new, 3:not_before}; both keys co-sign those exact bytes,
     * byte-identical to the Go/Python/Java references.
     */
    class RotationRecord(val oldId: String, val newId: String, val notBefore: Long) {
        /** Deterministic-CBOR encoding {1:old, 2:new, 3:not_before} - the bytes both keys sign. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.T(oldId)),
                    Cbor.Pair(Cbor.U(2), Cbor.T(newId)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(notBefore)),
                )
            )
        )
    }

    /**
     * Co-sign a rotation with BOTH the old and new keys (5.2): each is a RAW deterministic ML-DSA
     * signature over the record bytes (matching the reference cose.Signer.Sign). Returns
     * (oldSig, newSig). Both keys use the same [alg].
     */
    fun signRotation(r: RotationRecord, alg: Int, oldSeed: ByteArray, newSeed: ByteArray): Pair<ByteArray, ByteArray> {
        val m = r.bytes()
        val oldSig = Cose.mldsaSign(alg, oldSeed, m)
        val newSig = Cose.mldsaSign(alg, newSeed, m)
        return Pair(oldSig, newSig)
    }

    /**
     * Confirm a rotation is authorized: the old and new keys derive the ids in the record, and BOTH
     * signatures verify over the record bytes. A substitution not co-signed by the old key - or a key
     * whose id does not recompute - is RotationUnauthorized (5.2, 5.5). Fail-closed.
     */
    fun verifyRotation(
        r: RotationRecord,
        oldAlg: Int,
        oldPub: ByteArray,
        newAlg: Int,
        newPub: ByteArray,
        oldSig: ByteArray,
        newSig: ByteArray,
    ) {
        try {
            checkSigner(r.oldId, oldAlg, oldPub)
            checkSigner(r.newId, newAlg, newPub)
        } catch (e: NaalpException) {
            throw NaalpException("RotationUnauthorized", "rotation key id does not recompute from the key")
        }
        val m = r.bytes()
        if (!Cose.coseVerify1Raw(oldAlg, oldPub, m, oldSig) || !Cose.coseVerify1Raw(newAlg, newPub, m, newSig)) {
            throw NaalpException("RotationUnauthorized", "rotation not co-signed by both keys")
        }
    }

    // ---- key lifecycle: revocation, foreign-identity linkage, durable thread (design.md §5.3/§5.4,
    // R-1.4) ------------------------------------------------------------------------------------
    //
    // Ported from impl/go/identity/identity.go (VerifyRevocation/RevokedAt/ForeignLinkRecord/
    // VerifyForeignLink/RotationEvidence/Thread/Thread.Attributable/ResolveThread) and cross-checked
    // against impl/rust/src/identity.rs. Graded against the independent F3 oracle
    // (vectors/identity_records/cases.json, generated by tools/identity_records_oracle.py).

    /**
     * Marks a key dead from [notAfter] (§5.3). Signed bytes: {1:key, 2:not_after} — the
     * deterministic-CBOR map both the revoked key and a deployer-configured recovery key may sign.
     */
    class RevocationRecord(val key: String, val notAfter: Long) {
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.T(key)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(notAfter)),
                )
            )
        )
    }

    /**
     * Confirms a revocation is validly signed (§5.3): by the key it revokes, or by a
     * deployer-configured recovery key. [recoveryIds] is the deployer's set of authorized
     * recovery-key signer ids; a revocation whose signer is neither [r]'s key nor a member of
     * [recoveryIds] is rejected SignerMismatch (§5.5), fail-closed -- an empty [recoveryIds] admits
     * only the revoked key itself. The signer id is recomputed from the presented key and checked
     * BEFORE the signature (membership before signature, fail-closed).
     */
    fun verifyRevocation(r: RevocationRecord, alg: Int, pub: ByteArray, sig: ByteArray, recoveryIds: List<String>) {
        val id = signerId(alg, pub) // UnknownAlg propagates unchanged
        val authorized = id == r.key || recoveryIds.any { it == id }
        if (!authorized) {
            throw NaalpException("SignerMismatch", "signer id neither the revoked key nor an authorized recovery id")
        }
        if (!Cose.coseVerify1Raw(alg, pub, r.bytes(), sig)) {
            throw NaalpException("BadSignature", "revocation signature does not verify")
        }
    }

    /**
     * Reports whether an object fixed at authoritative position [posTime] is after the revocation
     * (KeyRevoked); objects fixed at or before notAfter stay valid (§5.3).
     */
    fun revokedAt(r: RevocationRecord, posTime: Long): Boolean = posTime > r.notAfter

    /**
     * Cross-signs a foreign identity to a signer id (§5.4). Signed bytes: {1:controls, 2:foreign_id,
     * 3:not_after}. It is signed by the FOREIGN identity's key.
     */
    class ForeignLinkRecord(val controls: String, val foreignId: String, val notAfter: Long) {
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.T(controls)),
                    Cbor.Pair(Cbor.U(2), Cbor.T(foreignId)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(notAfter)),
                )
            )
        )
    }

    /**
     * Reports whether a foreign-identity link confers linkage at time [now]. A non-NFC foreignId is
     * rejected (NonNFC). An expired link or a bad cross-signature confers NO linkage but is NOT
     * itself an error -- it simply does not link (the object remains valid on its own signature,
     * §5.4/§5.5). It NEVER overrides the key-derived id.
     */
    fun verifyForeignLink(r: ForeignLinkRecord, foreignAlg: Int, foreignPub: ByteArray, sig: ByteArray, now: Long): Boolean {
        requireNfc(r.foreignId)
        if (now > r.notAfter) return false // expired: confers no authority (ignored)
        if (!Cose.coseVerify1Raw(foreignAlg, foreignPub, r.bytes(), sig)) return false // bad/absent cross-sig: no linkage
        return true
    }

    // ---- durable identity thread (rotation-surviving attribution, R-1.4) -----------------------

    /** One verified rotation step: the record plus the two keys and their co-signatures. */
    class RotationEvidence(
        val record: RotationRecord,
        val oldAlg: Int,
        val oldPub: ByteArray,
        val newAlg: Int,
        val newPub: ByteArray,
        val oldSig: ByteArray,
        val newSig: ByteArray,
    )

    /** A durable identity: a root signer id continued by a chain of rotations. */
    class Thread(val root: String, val current: String, val chain: List<String>) {
        /**
         * Reports whether an object whose body signer id is [signer] belongs to this durable thread
         * (any id in the chain, including a pre-rotation key, R-1.4).
         */
        fun attributable(signer: String): Boolean = chain.any { it == signer }
    }

    /**
     * Verifies an ordered rotation chain and returns the durable identity thread. Each rotation must
     * be authorized (co-signed) and link the previous `new` to the next `old`; a break yields
     * RotationUnauthorized. A receipt signed under any id in Chain is attributable to Root, so it
     * stays attributable after rotation (R-1.4).
     */
    fun resolveThread(evs: List<RotationEvidence>): Thread {
        if (evs.isEmpty()) throw NaalpException("RotationUnauthorized", "empty rotation-evidence chain")
        val chain = ArrayList<String>()
        chain.add(evs[0].record.oldId)
        var prevNew = evs[0].record.oldId
        for (e in evs) {
            if (e.record.oldId != prevNew) {
                throw NaalpException("RotationUnauthorized", "rotation chain not contiguous")
            }
            verifyRotation(e.record, e.oldAlg, e.oldPub, e.newAlg, e.newPub, e.oldSig, e.newSig)
            chain.add(e.record.newId)
            prevNew = e.record.newId
        }
        return Thread(root = evs[0].record.oldId, current = prevNew, chain = chain)
    }
}
