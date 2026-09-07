// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

/**
 * C12 foreign-carriage-by-class known-answer test for the Kotlin SDK (design.md section 13;
 * R-14.1..14.8, R-18.6). Each carriage class is graded against its OWN per-class oracle at
 * vectors/carriage/<class>/cases.json (six independent corpora), none produced by this code.
 *
 * CORPUS-GRADED (pure): for every one of the six classes {jsonrpc, http, msg, stream, doc, opaque}
 * the carriage body encodes to the oracle bytes and the foreign message recovers OCTET-EXACT on a
 * round-trip (proving the foreign bytes are never re-serialized, R-14.4); the section-13.4
 * protocol-id range classification across 0x00..0xFF; a below-foreign failure reports NotDelivered;
 * an unrepresentable class is a typed MappingError, never a silent drop. Carriage bodies are UNSIGNED
 * -- the six per-class body_hex ARE the byte parity, and the corpus carries no signed pin (correct,
 * not a gap). CRYPTO-GRADED (real ML-DSA-65, Kotlin is a full-signature port): R-14.6 identity
 * containment over a REAL signed Envelope object -- the authorizing principal resolves to the N-AALP
 * signer, never the foreign principal named inside the carried bytes.
 *
 * KAT convention (a standalone main() exiting non-zero on any failure); the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Carriage] is absent until
 * Carriage.kt lands, so this fails RED with a kotlinc "unresolved reference: Carriage"; a mutation
 * that makes CarriageAuthority discard the signer flips "carriage authority == N-AALP signer".
 */

private var caFails = 0

private fun caCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        caFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

/** vectors/carriage/<cls>/cases.json, found by walking up from the run directory. */
private fun caFindVector(cls: String): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/carriage/$cls/cases.json not found")
        val p = File(File(cur, "vectors"), "carriage/$cls/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/carriage/$cls/cases.json not found from ${File(".").absolutePath}")
}

/** The string value of a "key": "value" pair (value may be empty). */
private fun caField(scope: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

/** The integer value of a "key": <number> pair. */
private fun caIntField(scope: String, key: String): Long {
    val m = Regex("\"$key\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

/** Run [block]; return "ok" if it returns, else the NaalpException kind. */
private fun caKind(block: () -> Unit): String = try {
    block()
    "ok"
} catch (e: NaalpException) {
    e.kind
}

private fun carriageRun() {
    // 1. per-class octet-exact round-trip (R-14.7): every class encodes to the oracle bytes and the
    //    foreign message recovers byte-identical, proving the foreign bytes are never re-serialized.
    val classDirs = listOf(
        "jsonrpc" to Carriage.CLASS_JSONRPC,
        "http" to Carriage.CLASS_HTTP,
        "msg" to Carriage.CLASS_MSG,
        "stream" to Carriage.CLASS_STREAM,
        "doc" to Carriage.CLASS_DOC,
        "opaque" to Carriage.CLASS_OPAQUE
    )
    for ((dir, expectClass) in classDirs) {
        val json = caFindVector(dir).readText(Charsets.UTF_8)
        val protocolId = caIntField(json, "protocol_id")
        val klass = caIntField(json, "class")
        val contentType = caIntField(json, "content_type")
        val correlation = Hex.decode(caField(json, "correlation_hex"))
        val method = caField(json, "method")
        val foreign = Hex.decode(caField(json, "foreign_hex"))
        val bodyHex = caField(json, "body_hex")

        caCheck("$dir class == oracle", klass.toString(), expectClass.toString())
        val cb = Carriage.carry(protocolId, klass, contentType, correlation, method, foreign)
        caCheck("$dir body == oracle", Hex.encode(cb.bytes()), bodyHex)
        // Round-trip: decode the carriage body and recover the foreign octets exactly.
        val rec = Carriage.carriageFromValue(Cbor.decode(cb.bytes()))
        caCheck("$dir foreign octet-exact round-trip", Hex.encode(rec.foreign), Hex.encode(foreign))
        caCheck("$dir recovered protocol_id", rec.protocolId.toString(), protocolId.toString())
        caCheck("$dir recovered class", rec.klass.toString(), klass.toString())
        caCheck("$dir recovered method", rec.method, method)
    }

    // 2. R-18.6: an undefined protocol carries under OPAQUE on an EXPERIMENTAL protocol id (no
    //    registration), byte-exact for an arbitrary blob.
    val opaqueJson = caFindVector("opaque").readText(Charsets.UTF_8)
    val opaqueId = caIntField(opaqueJson, "protocol_id")
    caCheck("opaque protocol id is experimental", Carriage.protocolRange(opaqueId), "experimental")
    val blob = byteArrayOf(0x00, 0x01, 0x02, 0xFF.toByte(), 0xFE.toByte(), 0x7F, 0x80.toByte())
    val opaqueCb = Carriage.carry(opaqueId, Carriage.CLASS_OPAQUE, 1, ByteArray(0), "", blob)
    val opaqueRec = Carriage.carriageFromValue(Cbor.decode(opaqueCb.bytes()))
    caCheck("opaque blob recovered exactly", Hex.encode(opaqueRec.foreign), Hex.encode(blob))

    // 3. section-13.4 protocol-id range boundaries.
    val ranges = mapOf(
        0x00L to "reserved", 0x01L to "standards", 0x0FL to "standards",
        0x10L to "experimental", 0x7FL to "experimental", 0x80L to "private", 0xFFL to "private"
    )
    for ((id, want) in ranges) {
        caCheck("protocolRange(0x${id.toString(16)})", Carriage.protocolRange(id), want)
    }

    // 4. R-14.8: an unrepresentable class is a typed MappingError, never a silent drop.
    caCheck("unknown class rejected", caKind { Carriage.carry(0x10, 99, 0, ByteArray(0), "x", "y".toByteArray()) }, "MappingError")

    // 5. R-14.8: a below-foreign failure reports NotDelivered; a success reports delivered.
    caCheck("failed delivery reports NotDelivered", caKind { Carriage.report(false) }, "NotDelivered")
    caCheck("successful delivery reported", Carriage.report(true).delivered.toString(), "true")

    // 6. R-14.6 identity containment over a REAL signed Envelope object: a foreign principal named
    //    inside the foreign bytes confers NO authority; the authorizing principal is the N-AALP signer
    //    of the carriage object (a normal signed envelope object, R-14.2), and the foreign body still
    //    recovers octet-exact (carrying, but not empowering, the foreign principal).
    val seed = ByteArray(32) { 80.toByte() }
    val pk = Cose.mldsaKeygen("ML-DSA-65", seed)
    val foreign = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"from\":\"attacker-principal\"}}".toByteArray(Charsets.UTF_8)
    val carriageCb = Carriage.carry(0x01, Carriage.CLASS_JSONRPC, 0, byteArrayOf(1, 2, 3, 4), "tools/call", foreign)
    val obj = Envelope.Object(
        kind = 0, channel = 13, signer = pk, created = 100, effect = 0,
        body = carriageCb.toValue(), profile = Cose.PROFILE_PUBLIC
    )
    val signed = Envelope.sign(obj, Cose.ALG_MLDSA65, seed)
    val verified = Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk, { _, _ -> true }, signed)
    val authority = Carriage.carriageAuthority(verified)
    caCheck("carriage authority == N-AALP signer", Hex.encode(authority), Hex.encode(pk))
    caCheck("authority not leaked from foreign", authority.toString(Charsets.ISO_8859_1).contains("attacker-principal").toString(), "false")
    val recovered = Carriage.carriageFromValue(verified.body)
    caCheck("foreign recovered octet-exact from signed object", Hex.encode(recovered.foreign), Hex.encode(foreign))
    caCheck("foreign still carries the (non-authoritative) principal", recovered.foreign.toString(Charsets.ISO_8859_1).contains("attacker-principal").toString(), "true")
}

fun main() {
    println("carriage conformance (Kotlin) -- graded vs vectors/carriage/<class>/cases.json (6 oracles)")
    carriageRun()
    println(if (caFails == 0) "CarriageTests: PASS" else "CarriageTests: FAIL ($caFails)")
    exitProcess(if (caFails == 0) 0 else 1)
}
