// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * examples/SecureObject.kt — build, sign, verify, and tamper-check a full N-AALP object.
 *
 * Run: compile the SDK sources plus this file into a jar, then
 *   java -cp "secure-object.jar;<bcprov.jar>" sh.bubblefish.naalp.SecureObjectKt
 *
 * Expected output:
 *   signer   bciq...
 *   signed   <N> bytes, verifies=true
 *   tampered rejected: BadSignature
 */
fun main() {
    // a deterministic 32-byte key seed (use a real random seed in production)
    val seed = ByteArray(32) { 0x2a }
    val alg = Naalp.ALG_MLDSA65
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val signerId = Identity.signerId(alg, pk)
    println("signer   $signerId")

    // the args object whose content id the approval authorizes
    val argsObj = Envelope.Object(
        kind = 0, channel = 0, signer = ByteArray(0), created = 0, effect = 0,
        body = Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.T("the-args")))),
    )
    val argsId = argsObj.contentId()

    // a Governance Approval object (channel 0x0004, kind 1) on the Public profile
    val approval = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.B(argsId)),
            Cbor.Pair(Cbor.U(2), Cbor.T(signerId)),
            Cbor.Pair(Cbor.U(3), Cbor.U(2)),                                   // granted effect: non_idempotent_write
            Cbor.Pair(Cbor.U(4), Cbor.B(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))), // nonce
            Cbor.Pair(Cbor.U(5), Cbor.U(1785000000000L)),                      // not_after (epoch ms)
        )
    )
    val obj = Envelope.Object(
        kind = 1, channel = 4, tier = 0, signer = signerId.toByteArray(Charsets.UTF_8),
        created = 1785000000000L, effect = 2, profile = Naalp.PROFILE_PUBLIC, body = approval,
    )

    val signed = Naalp.sign(obj, alg, seed)
    val got = Naalp.verify(Naalp.PROFILE_PUBLIC, alg, pk, { c, k -> c == 4L && k == 1L }, signed)
    println("signed   ${signed.size} bytes, verifies=${got.kind == 1L && got.channel == 4L}")

    val tampered = signed.copyOf()
    tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    try {
        Naalp.verify(Naalp.PROFILE_PUBLIC, alg, pk, { _, _ -> true }, tampered)
        println("tampered NOT rejected (bug)")
    } catch (e: NaalpException) {
        println("tampered rejected: ${e.kind}")
    }
}
