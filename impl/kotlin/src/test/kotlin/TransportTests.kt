// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

/**
 * C11 transport-binding known-answer test for the Kotlin SDK (design.md §12; R-13.1..13.4), graded
 * against the shared independent corpus vectors/transport/cases.json (NOT produced by this code): the
 * media type, the four bindings' confidentiality/peer-auth guarantees, the framing round-trip, and the
 * §12.3/§12.4 emit-boundary matrix. Every property here is a PURE deterministic assertion (no crypto),
 * so all of transport is corpus-graded on the Kotlin port.
 *
 * KAT convention (a standalone main() that runs checks and exits non-zero on any failure, mirroring
 * WorkedExampleKat.kt); the filename carries the "Tests" token the ten-language-parity gate indexes as
 * test evidence. Written test-first: [Transport] is absent until Transport.kt lands, so this fails RED
 * with a kotlinc "unresolved reference: Transport"; a mutation to a binding guarantee flips the
 * "variant guarantees: websocket+ws" and "emit websocket+ws sensitive=1 peer=0" checks.
 *
 * Run (main()-driven, no test framework): compile the SDK sources plus this KAT into a jar, then run
 * sh.bubblefish.naalp.TransportTestsKt (on Windows the classpath separator is ';').
 */

private var transportFails = 0

private fun tCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        transportFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- minimal regex JSON access (no JSON library on the Kotlin port) ----

private fun tFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/transport/cases.json not found")
        val p = File(File(cur, "vectors"), "transport/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/transport/cases.json not found from ${File(".").absolutePath}")
}

/** The string value of a "key": "value" pair inside [scope] (value may be empty). */
private fun tStr(scope: String, key: String): String {
    val m = Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

/** The boolean value of a "key": true|false pair inside [scope]. */
private fun tBool(scope: String, key: String): Boolean {
    val m = Regex("\"$key\"\\s*:\\s*(true|false)").find(scope)
        ?: throw AssertionError("boolean key not found: $key")
    return m.groupValues[1] == "true"
}

/**
 * The flat { ... } object blocks of the array named [arrayKey]. The transports and emit_matrix arrays
 * contain only flat objects (no nested braces), so splitting on innermost {...} within the array body
 * is exact.
 */
private fun tObjectBlocks(json: String, arrayKey: String): List<String> {
    val a = Regex("\"$arrayKey\"\\s*:\\s*\\[(.*?)\\]", RegexOption.DOT_MATCHES_ALL).find(json)
        ?: throw AssertionError("array key not found: $arrayKey")
    return Regex("\\{([^{}]*)\\}", RegexOption.DOT_MATCHES_ALL).findAll(a.groupValues[1])
        .map { it.groupValues[1] }.toList()
}

private val OBJ = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())

private fun transportRun() {
    val json = tFindVector().readText(Charsets.UTF_8)

    // 1. media type is the one-object-per-representation N-AALP type (§12.1).
    tCheck("media type", Transport.MEDIA_TYPE, tStr(json, "media_type"))

    // 2. every transport variant's confidentiality/peer-auth guarantees == the oracle.
    for (b in tObjectBlocks(json, "transports")) {
        val name = tStr(b, "name")
        val t = Transport.byName(name)
        tCheck("variant present: $name", if (t == null) "absent" else "present", "present")
        if (t != null) {
            val got = (if (t.confidential) "1" else "0") + (if (t.peerAuthenticated) "1" else "0")
            val want = (if (tBool(b, "confidential")) "1" else "0") + (if (tBool(b, "peer_authenticated")) "1" else "0")
            tCheck("variant guarantees: $name", got, want)
        }
    }

    // 3. framing round-trips the object bytes verbatim; the media type is the N-AALP type (R-13.2).
    val np = Transport.byName("npamp") ?: throw AssertionError("npamp absent")
    val mu = Transport.frame(np, byteArrayOf(1, 2, 3))
    tCheck("frame media type", mu.mediaType, Transport.MEDIA_TYPE)
    tCheck("frame roundtrip object", Hex.encode(mu.objectBytes()), "010203")

    // 4. a message unit with a wrong media type is rejected Malformed (fail-closed).
    var badKind = "no-error"
    try {
        Transport.MessageUnit("npamp", "application/json", byteArrayOf(9)).objectBytes()
    } catch (e: NaalpException) {
        badKind = e.kind
    }
    tCheck("wrong media type rejected", badKind, "Malformed")

    // 5. the §12.3 confidentiality / §12.4 peer-auth emit-boundary matrix == the oracle, row by row.
    for (c in tObjectBlocks(json, "emit_matrix")) {
        val tn = tStr(c, "transport")
        val sensitive = tBool(c, "sensitive")
        val requirePeerAuth = tBool(c, "require_peer_auth")
        val want = tStr(c, "result")
        val t = Transport.byName(tn)
        val result: String
        if (t == null) {
            result = "unknown-transport"
        } else {
            result = try {
                val emitted = Transport.emit(t, OBJ, sensitive, requirePeerAuth)
                if (emitted.objectBytes().contentEquals(OBJ)) "ok" else "framed-wrong-bytes"
            } catch (e: NaalpException) {
                e.kind
            }
        }
        tCheck(
            "emit $tn sensitive=${if (sensitive) "1" else "0"} peer=${if (requirePeerAuth) "1" else "0"}",
            result, want
        )
    }
}

fun main() {
    println("transport conformance (Kotlin) — graded vs vectors/transport/cases.json")
    transportRun()
    println(if (transportFails == 0) "TransportTests: PASS" else "TransportTests: FAIL ($transportFails)")
    exitProcess(if (transportFails == 0) 0 else 1)
}
