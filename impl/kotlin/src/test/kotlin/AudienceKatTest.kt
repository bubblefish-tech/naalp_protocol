// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * The object-audience (field 13, §2.5.3) known-answer + gate test for the Kotlin SDK, in the same
 * plain-main() KAT style as WorkedExampleKatTest (no test framework).
 *
 * Three properties, all mutation-surviving:
 *  1. BYTE MATCH -- an audience-bearing object reproduces the independent oracle's content id AND
 *     payload (over the body WITH the audience), and a NO-audience object reproduces the base
 *     content id -- proving omit-when-empty additivity byte-for-byte
 *     (Kotlin == Go == Rust == ... == the oracle). contentId()/bodyMap() run the impl encoder.
 *  2. checkAudience -- the three-branch point-of-use gate.
 *  3. consumeObject -- enforced at the consume choke point BEFORE the compare-and-set: wrong/absent
 *     -> WrongAudience with no append; unnamed ledger -> LedgerUnsigned; correct -> consumes once.
 *
 * Run: compile the SDK sources plus this file, then
 *   java -cp "aud-kat.jar;<bcprov.jar>;<kotlin-stdlib.jar>" sh.bubblefish.naalp.AudienceKatTestKt
 */

private val A_SIGNER = Hex.decode("5349474e45525f41") // "SIGNER_A"
private const val A_AUDIENCE = "consuming-authority-xyz"

private class AudFailure(msg: String) : RuntimeException(msg)

private fun aeq(what: String, got: Any?, want: Any?) {
    if (got != want) throw AudFailure("$what:\n  got  = $got\n  want = $want")
}

private fun audienceObject(): Envelope.Object =
    Envelope.Object(
        kind = 2, channel = 4, tier = 0, signer = A_SIGNER, created = 1785000000000L,
        effect = 2, profile = 1, body = Cbor.T("hello"), audience = A_AUDIENCE,
    )

private fun plainObject(): Envelope.Object =
    Envelope.Object(
        kind = 2, channel = 4, tier = 0, signer = A_SIGNER, created = 1785000000000L,
        effect = 2, profile = 1, body = Cbor.T("hello"),
    )

private fun gateObject(aud: String): Envelope.Object =
    Envelope.Object(
        kind = 2, channel = 4, signer = A_SIGNER, created = 0, effect = 0,
        body = Cbor.T("x"), profile = 1, audience = aud,
    )

private fun findEnvelopeVector(): File? {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: return null
        val p = File(cur, "vectors/envelope/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    return null
}

/** hex value of [key] in the object_with_audience block (audience=true) or the base object block. */
private fun hexInBlock(json: String, audience: Boolean, key: String): String {
    val split = json.indexOf("object_with_audience")
    val region = if (audience) json.substring(split) else json.substring(0, split)
    val m = Regex("\"$key\"\\s*:\\s*\"([0-9a-f]+)\"").find(region)
        ?: throw AudFailure("$key not found in ${if (audience) "audience" else "base"} block")
    return m.groupValues[1]
}

private fun expectKind(what: String, wantKind: String, fn: () -> Unit) {
    try {
        fn()
        throw AudFailure("$what: expected $wantKind, no exception thrown")
    } catch (e: NaalpException) {
        aeq("$what.kind", e.kind, wantKind)
    }
}

private fun aid(): ByteArray = ByteArray(50) { it.toByte() }

fun main() {
    println("AudienceKatTest — object audience field 13 (§2.5.3): byte-match + gates")

    // 1. BYTE MATCH vs the independent oracle
    val vec = findEnvelopeVector()
    if (vec != null) {
        val json = vec.readText(Charsets.UTF_8)
        val a = audienceObject()
        a.id = a.contentId()
        aeq("audience content_id", Hex.encode(a.contentId()), hexInBlock(json, true, "content_id_hex"))
        aeq("audience payload", Hex.encode(Cbor.encode(a.bodyMap(true))), hexInBlock(json, true, "payload_hex"))
        aeq("plain content_id (additive)", Hex.encode(plainObject().contentId()), hexInBlock(json, false, "content_id_hex"))
        if (Hex.encode(audienceObject().contentId()) == Hex.encode(plainObject().contentId())) {
            throw AudFailure("audience and no-audience content ids must differ")
        }
        println("  ok  byte-match vs oracle (audience content_id + payload + additive plain content_id)")
    } else {
        println("  ..  vectors/envelope/cases.json not found; skipped the byte compare")
    }

    // 2. checkAudience three branches (6 cases)
    Envelope.checkAudience(gateObject("authority-A"), "authority-A", true)   // pass
    Envelope.checkAudience(gateObject(""), "authority-A", false)             // pass
    Envelope.checkAudience(gateObject("authority-A"), "authority-A", false)  // pass
    expectKind("consume-once foreign", "WrongAudience") { Envelope.checkAudience(gateObject("authority-B"), "authority-A", true) }
    expectKind("consume-once absent", "WrongAudience") { Envelope.checkAudience(gateObject(""), "authority-A", true) }
    expectKind("foreign unrestricted", "WrongAudience") { Envelope.checkAudience(gateObject("authority-B"), "authority-A", false) }
    println("  ok  checkAudience three branches (6 cases)")

    // 3. consumeObject choke point (a fresh WAL per case)
    run {
        val p = File.createTempFile("naalp-audience", ".wal")
        val led = Approval.openLedger(p.absolutePath, "authority-A")
        expectKind("consumeObject wrong", "WrongAudience") { led.consumeObject(gateObject("authority-B"), aid(), "consumer") }
        aeq("wrong audience no append", led.size(), 0)
        led.close(); p.delete()
    }
    run {
        val p = File.createTempFile("naalp-audience", ".wal")
        val led = Approval.openLedger(p.absolutePath, "authority-A")
        expectKind("consumeObject absent", "WrongAudience") { led.consumeObject(gateObject(""), aid(), "consumer") }
        aeq("absent audience no append", led.size(), 0)
        led.close(); p.delete()
    }
    run {
        val p = File.createTempFile("naalp-audience", ".wal")
        val led = Approval.openLedger(p.absolutePath, "authority-A")
        led.consumeObject(gateObject("authority-A"), aid(), "consumer")
        aeq("correct audience consumes once", led.size(), 1)
        expectKind("consumeObject second", "AlreadyConsumed") { led.consumeObject(gateObject("authority-A"), aid(), "consumer") }
        led.close(); p.delete()
    }
    run {
        val p = File.createTempFile("naalp-audience", ".wal")
        val led = Approval.openLedger(p.absolutePath, "")
        expectKind("consumeObject unnamed", "LedgerUnsigned") { led.consumeObject(gateObject("authority-A"), aid(), "consumer") }
        led.close(); p.delete()
    }
    println("  ok  consumeObject choke point (wrong/absent/correct/unnamed)")

    println("AudienceKatTest: PASS")
}
