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
}
