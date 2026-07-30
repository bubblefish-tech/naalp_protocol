// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * The full-object known-answer test: the reference worked object (fixed seed 0x2a*32, ML-DSA-65)
 * MUST be reproduced byte-for-byte, and the resulting object MUST verify and reject tampering.
 * The self-contained KAT anchors (signer id, content id, args id) come from
 * vectors/worked/example.json; when that committed vector is found on disk the entire
 * signed_object_hex is additionally compared byte-for-byte.
 *
 * Run (main()-driven, no test framework): compile the SDK sources plus this file into a jar, then
 *   java -cp "worked-kat.jar;<bcprov.jar>" sh.bubblefish.naalp.WorkedExampleKatKt
 */

private const val SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua"
private const val CONTENT_ID_HEX =
    "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134"
private const val ARGS_ID_HEX =
    "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"

private val SEED = ByteArray(32) { 0x2a }
private const val ALG = Cose.ALG_MLDSA65

private class Failure(msg: String) : RuntimeException(msg)

private fun eq(what: String, got: Any?, want: Any?) {
    if (got != want) throw Failure("$what:\n  got  = $got\n  want = $want")
    println("  ok  $what")
}

private fun workedObject(): Triple<ByteArray, String, Envelope.Object> {
    val pk = Cose.mldsaKeygen("ML-DSA-65", SEED)
    val signerId = Identity.signerId(ALG, pk)
    val body = Cbor.M(
        listOf(
            Cbor.Pair(Cbor.U(1), Cbor.B(Hex.decode(ARGS_ID_HEX))),
            Cbor.Pair(Cbor.U(2), Cbor.T(signerId)),
            Cbor.Pair(Cbor.U(3), Cbor.U(2)),
            Cbor.Pair(Cbor.U(4), Cbor.B(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))),
            Cbor.Pair(Cbor.U(5), Cbor.U(1785000000000L)),
        )
    )
    val obj = Envelope.Object(
        kind = 1, channel = 4, tier = 0,
        signer = signerId.toByteArray(Charsets.UTF_8),
        created = 1785000000000L, effect = 2, profile = Cose.PROFILE_PUBLIC, body = body,
    )
    return Triple(pk, signerId, obj)
}

/** Walk up from the working directory to find the committed worked vector, if present. */
private fun findVector(): File? {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: return null
        val p = File(cur, "vectors/worked/example.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    return null
}

private fun hexFor(json: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\"([0-9a-f]+)\"").find(json)
        ?: throw Failure("key $key not found in committed vector")
    return m.groupValues[1]
}

fun main() {
    println("WorkedExampleKat — reproduce the byte-level worked object (ML-DSA-65, seed 0x2a*32)")

    val (pk, signerId, obj) = workedObject()

    // 1. signer id + content id
    eq("signer id", signerId, SIGNER_ID)
    eq("content id", Hex.encode(obj.contentId()), CONTENT_ID_HEX)

    // 2. sign -> signed object bytes
    val signed = Envelope.sign(obj, ALG, SEED)
    val signedHex = Hex.encode(signed)

    // 3. sign/verify round-trip returns the decoded object
    val got = Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, { c, k -> c == 4L && k == 1L }, signed)
    eq("round-trip (kind,channel,effect)", listOf(got.kind, got.channel, got.effect), listOf(1L, 4L, 2L))

    // 4. tamper the last byte -> BadSignature
    val tampered = signed.copyOf()
    tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    var tamperKind = ""
    try {
        Envelope.verify(Cose.PROFILE_PUBLIC, ALG, pk, { _, _ -> true }, tampered)
    } catch (e: NaalpException) {
        tamperKind = e.kind
    }
    eq("tamper rejected", tamperKind, "BadSignature")

    // 5. byte-exact vs the committed vector, when it is on disk
    val vec = findVector()
    if (vec != null) {
        val json = vec.readText(Charsets.UTF_8)
        eq("signed_object_hex (committed vector)", signedHex, hexFor(json, "signed_object_hex"))
        eq("content_id_hex (committed vector)", Hex.encode(obj.contentId()), hexFor(json, "content_id_hex"))
        eq("payload_body_hex (committed vector)", Hex.encode(Cbor.encode(obj.bodyMap(true))), hexFor(json, "payload_body_hex"))
    } else {
        println("  ..  committed vector not found on disk; skipped the full byte compare")
    }

    println("WorkedExampleKat: PASS")
}
