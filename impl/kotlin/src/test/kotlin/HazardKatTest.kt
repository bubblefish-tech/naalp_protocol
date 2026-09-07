// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * Manufacturing Add-ons Component F (naalp-hazard) known-answer test for the Kotlin SDK, graded
 * against the independent, non-circular oracle `vectors/hazard/cases.json`
 * (tools/hazard_oracle.py) -- mirroring impl/rust/naalp-hazard/src/lib.rs's test module and
 * impl/csharp/test/HazardKatTest.cs, i.e. Kotlin == Rust == C# == oracle.
 *
 * Properties covered (mutation anchors noted):
 *  1. FROM-CODE FAIL-CLOSED -- every from_code row matches the oracle; absent/unknown/out-of-range
 *     input normalizes to MOTION_IN_SHARED_SPACE (F2); the four in-range codes decode to
 *     themselves.
 *  2. BYTE-LEVEL -- claim/authorization encoding and content id match the oracle's body/content-id
 *     hex for every `bodies` row.
 *  3. ROUND-TRIP -- fromValue(toValue(x)) reproduces x's class and bytes for every `bodies` row.
 *  4. COVERAGE MATRIX [MUTATION ANCHOR] -- hazardAuthorized reproduces the oracle's allow/deny
 *     verdict for every `coverage` row; a constant "always authorized" fails every deny row, a
 *     constant "always denied" fails every allow row.
 *  5. ABSENT CLAIM -- hazardAuthorizedOptional(null, grant) denies with the distinct HazardUnknown
 *     error, never HazardNotCovered; a present, well-covered claim still authorizes through the
 *     same entry point.
 *  6. MALFORMED BODIES REJECTED -- fail-closed on empty axes, min > max, non-NFC frame, wrong
 *     shape, a partial body, and an explicit out-of-range class ON THE WIRE (distinct from the
 *     absent/unknown fail-closed normalization path).
 *  7. CONTAINMENT TRUTH TABLES -- spatialContained / envelopeContained direct assertions
 *     independent of the oracle file.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure (mirrors ChannelsKatTest.kt
 * / ApprovalKatTest.kt / RotationKatTest.kt); the filename carries the "KatTest" token the
 * ten-language-parity gate indexes.
 *
 * Run (from impl/kotlin/):
 *   kotlinc src/main/kotlin src/test/kotlin/HazardKatTest.kt -include-runtime -d out/hazard-kat.jar
 *   java -cp out/hazard-kat.jar sh.bubblefish.naalp.HazardKatTestKt
 */

// ---- balanced-brace / regex JSON access (string-aware; mirrors ChannelsKatTest.kt) ----------------

private class HzFailure(msg: String) : RuntimeException(msg)

private var hzFails = 0

private fun hzOk(name: String) = println("  ok   $name")

private fun hzFail(name: String, detail: String) {
    hzFails++
    println("  FAIL $name\n       $detail")
}

private fun hzCheck(name: String, got: String, want: String) {
    if (got == want) hzOk(name) else hzFail(name, "got  $got\n       want $want")
}

private fun hzCheckBool(name: String, got: Boolean, want: Boolean) {
    if (got == want) hzOk(name) else hzFail(name, "got $got want $want")
}

/** Run [block]; require it throws a [NaalpException] whose kind == [wantKind]. */
private fun hzExpectThrows(name: String, wantKind: String, block: () -> Unit) {
    try {
        block()
        hzFail(name, "expected $wantKind, no exception thrown")
    } catch (e: NaalpException) {
        hzCheck(name, e.kind, wantKind)
    }
}

/** Run [block]; require it does NOT throw. */
private fun hzExpectOk(name: String, block: () -> Unit) {
    try {
        block()
        hzOk(name)
    } catch (e: NaalpException) {
        hzFail(name, "expected no error, got ${e.kind}: ${e.message}")
    }
}

private fun bracketExtent(s: String, openCh: Char, closeCh: Char, start: Int): Int {
    var depth = 0
    var inString = false
    var escape = false
    for (i in start until s.length) {
        val c = s[i]
        if (inString) {
            when {
                escape -> escape = false
                c == '\\' -> escape = true
                c == '"' -> inString = false
            }
            continue
        }
        when {
            c == '"' -> inString = true
            c == openCh -> depth++
            c == closeCh -> {
                depth--
                if (depth == 0) return i
            }
        }
    }
    return -1
}

/** The raw substring (including delimiters) of the value following "key": in [s], for an object
 *  ("{...}") or array ("[...]") value. */
private fun rawValue(s: String, key: String): String? {
    val idx = s.indexOf("\"$key\"")
    if (idx < 0) return null
    val after = s.substring(idx)
    val colon = after.indexOf(':')
    if (colon < 0) return null
    val rest = after.substring(colon + 1).trimStart()
    if (rest.isEmpty()) return null
    val opener = rest[0]
    val closer = when (opener) {
        '{' -> '}'
        '[' -> ']'
        else -> return null
    }
    val end = bracketExtent(rest, opener, closer, 0)
    if (end < 0) return null
    return rest.substring(0, end + 1)
}

private fun splitJsonObjects(body: String): List<String> {
    val out = ArrayList<String>()
    var depth = 0
    var start = -1
    var inString = false
    var escape = false
    for (i in body.indices) {
        val c = body[i]
        if (inString) {
            when {
                escape -> escape = false
                c == '\\' -> escape = true
                c == '"' -> inString = false
            }
            continue
        }
        when (c) {
            '"' -> inString = true
            '{' -> {
                if (depth == 0) start = i
                depth++
            }
            '}' -> {
                depth--
                if (depth == 0 && start >= 0) {
                    out.add(body.substring(start, i + 1))
                    start = -1
                }
            }
        }
    }
    return out
}

/** The list of raw JSON object strings inside "key": [ {...}, {...}, ... ]. */
private fun objectArrayField(s: String, key: String): List<String> {
    val raw = rawValue(s, key) ?: return emptyList()
    if (!raw.startsWith("[")) return emptyList()
    return splitJsonObjects(raw.substring(1, raw.length - 1))
}

private fun nullableField(s: String, key: String): String? {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(null|\"(?:[^\"\\\\]|\\\\.)*\"|-?[0-9]+|true|false)").find(s) ?: return null
    val raw = m.groupValues[1]
    if (raw == "null") return null
    return if (raw.startsWith("\"")) raw.substring(1, raw.length - 1) else raw
}

/** Decode JSON string escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX`) -- the
 *  oracle's `unicode_frame` case carries a `é` escape, which a naive quote-strip must not
 *  pass through literally as the six-character text `é`. */
private fun jsonUnescape(s: String): String {
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '\\' && i + 1 < s.length) {
            when (val e = s[i + 1]) {
                '"' -> { sb.append('"'); i += 2 }
                '\\' -> { sb.append('\\'); i += 2 }
                '/' -> { sb.append('/'); i += 2 }
                'b' -> { sb.append('\b'); i += 2 }
                'f' -> { sb.append('\u000C'); i += 2 }
                'n' -> { sb.append('\n'); i += 2 }
                'r' -> { sb.append('\r'); i += 2 }
                't' -> { sb.append('\t'); i += 2 }
                'u' -> {
                    if (i + 6 <= s.length) {
                        sb.append(s.substring(i + 2, i + 6).toInt(16).toChar())
                        i += 6
                    } else {
                        sb.append(e); i += 2
                    }
                }
                else -> { sb.append(e); i += 2 }
            }
        } else {
            sb.append(c)
            i += 1
        }
    }
    return sb.toString()
}

/** A quoted-string field, JSON-unescaped (unlike [nullableField], which leaves escapes raw for
 *  the numeric/bool/null callers that never need them). */
private fun strField(s: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(s)
        ?: throw HzFailure("string key not found: $key")
    return jsonUnescape(m.groupValues[1])
}

/** An unsigned 64-bit-safe numeric field: parses via [java.lang.Long.parseUnsignedLong] so a value
 *  up to 2^64-1 -- carried as either a JSON number or (past 2^63-1) a decimal string in the oracle
 *  -- decodes to the exact bit pattern [Cbor.U] carries, never overflowing/throwing the way a plain
 *  signed `.toLong()` would (mirrors RecheckSignerCounterKatTest.kt's uintField). */
private fun uField(s: String, key: String): Long =
    nullableField(s, key)?.let { java.lang.Long.parseUnsignedLong(it) } ?: throw HzFailure("uint key not found: $key")

private fun nullableUField(s: String, key: String): Long? =
    nullableField(s, key)?.let { java.lang.Long.parseUnsignedLong(it) }

/** The list of `[min, max]` signed-integer pairs inside "axes": [ [a,b], [c,d], ... ] -- a flat
 *  regex scan suffices because axes never nest a string or another array inside a pair. */
private fun axesFrom(s: String): List<Pair<Long, Long>> {
    val raw = rawValue(s, "axes") ?: throw HzFailure("missing axes")
    return Regex("\\[\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*\\]").findAll(raw)
        .map { m -> m.groupValues[1].toLong() to m.groupValues[2].toLong() }
        .toList()
}

private fun envFrom(o: String): Hazard.HazardEnvelope {
    val frame = strField(o, "frame")
    val axes = axesFrom(o)
    val speed = uField(o, "speed_bound_mm_s")
    val notBefore = uField(o, "not_before")
    val notAfter = uField(o, "not_after")
    return Hazard.HazardEnvelope(Hazard.SpatialBounds(frame, axes), speed, Hazard.HazardWindow(notBefore, notAfter))
}

private fun findVector(rel: String): File {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: throw HzFailure("$rel not found")
        val p = File(cur, rel)
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw HzFailure("$rel not found from ${File(".").absolutePath}")
}

private fun vectorJson(): String = findVector("vectors/hazard/cases.json").readText(Charsets.UTF_8)

// ==== 1. FROM-CODE FAIL-CLOSED (F2) matches the oracle ==============================================

private fun fromCodeFailClosedRun() {
    val c = vectorJson()
    for (row in objectArrayField(c, "from_code")) {
        val input = nullableUField(row, "code")
        val want = uField(row, "class")
        hzCheck("from_code($input)", Hazard.HazardClass.fromCode(input).code.toString(), want.toString())
    }

    // Explicit oracle-independent assertions of the two named fail-closed cases (F2).
    hzCheckBool("from_code(null) == MOTION_IN_SHARED_SPACE",
        Hazard.HazardClass.fromCode(null) == Hazard.HazardClass.MOTION_IN_SHARED_SPACE, true)
    hzCheckBool("from_code(9) == MOTION_IN_SHARED_SPACE",
        Hazard.HazardClass.fromCode(9L) == Hazard.HazardClass.MOTION_IN_SHARED_SPACE, true)
    // u64::MAX (0xFFFFFFFFFFFFFFFF) as its Long bit pattern is -1L; an out-of-u8-range code must
    // still normalize, not throw or wrap into an in-range class.
    hzCheckBool("from_code(u64::MAX) == MOTION_IN_SHARED_SPACE",
        Hazard.HazardClass.fromCode(-1L) == Hazard.HazardClass.MOTION_IN_SHARED_SPACE, true)

    // The five in-range codes decode to themselves, never collapsing to the default.
    for (code in 0L..4L) {
        hzCheck("from_code($code) round-trips its own code", Hazard.HazardClass.fromCode(code).code.toString(), code.toString())
    }
}

// ==== 2/3. BYTE-LEVEL + ROUND-TRIP: encode matches the independent oracle ============================

private fun bytesAndRoundTripRun() {
    val c = vectorJson()
    for (row in objectArrayField(c, "bodies")) {
        val name = strField(row, "name")
        val cls = Hazard.HazardClass.fromCode(uField(row, "class"))
        val e = envFrom(row)
        val claim = Hazard.HazardClaim(cls, e)
        val auth = Hazard.HazardAuthorization(cls, e)
        val wantBody = strField(row, "body_hex")
        hzCheck("$name claim bytes == oracle body_hex", Hex.encode(claim.bytes()), wantBody)
        hzCheck("$name authorization bytes == oracle body_hex (same shape as claim)", Hex.encode(auth.bytes()), wantBody)
        hzCheck("$name claim content-id == oracle", Hex.encode(claim.contentId()), strField(row, "content_id_hex"))

        val got = Hazard.HazardClaim.fromValue(claim.toValue())
        hzCheckBool("$name round-trip class", got.hazardClass == claim.hazardClass, true)
        hzCheck("$name round-trip bytes", Hex.encode(got.bytes()), Hex.encode(claim.bytes()))
    }
}

// ==== 4. COVERAGE MATRIX [MUTATION ANCHOR] ============================================================
//
// A constant "always authorized" hazardAuthorized fails every deny row below; a constant "always
// denied" fails every allow row. The matrix needs both to be a real mutation anchor.

private fun coverageMatchesOracleRun() {
    val c = vectorJson()
    val rows = objectArrayField(c, "coverage")
    hzCheckBool("coverage matrix non-empty", rows.isNotEmpty(), true)
    var allows = 0
    var denies = 0
    for (row in rows) {
        val name = strField(row, "name")
        val claim = Hazard.HazardClaim(
            Hazard.HazardClass.fromCode(nullableUField(row, "claim_class_code")),
            envFrom(rawValue(row, "claim_envelope")!!),
        )
        val grant = Hazard.HazardAuthorization(
            Hazard.HazardClass.fromCode(nullableUField(row, "grant_class_code")),
            envFrom(rawValue(row, "grant_envelope")!!),
        )
        val wantOk = nullableField(row, "authorized") == "true"
        if (wantOk) {
            allows++
            hzExpectOk("$name authorized") { Hazard.hazardAuthorized(claim, grant) }
        } else {
            denies++
            hzExpectThrows("$name denied", "HazardNotCovered") { Hazard.hazardAuthorized(claim, grant) }
        }
    }
    hzCheckBool("matrix needs both allows and denies", allows > 0 && denies > 0, true)
}

// ==== 5. ABSENT CLAIM: distinct HazardUnknown, never HazardNotCovered ================================
//
// F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all): distinct from
// an in-range-but-mismatched class, and distinct from an unrecognized class byte inside a present
// claim (covered by coverageMatchesOracleRun's normalized rows).

private fun absentClaimDeniesWithDistinctErrorRun() {
    val grant = Hazard.HazardAuthorization(
        Hazard.HazardClass.TOOL_ACTUATION,
        Hazard.HazardEnvelope(
            Hazard.SpatialBounds("cell-7/world", listOf(0L to 1000L, 0L to 1000L, 0L to 500L)),
            500L, Hazard.HazardWindow(0L, 1000L),
        ),
    )
    hzExpectThrows("absent claim denies with HazardUnknown", "HazardUnknown") {
        Hazard.hazardAuthorizedOptional(null, grant)
    }
    // A present, well-covered claim still authorizes through the same entry point.
    val claim = Hazard.HazardClaim(
        Hazard.HazardClass.TOOL_ACTUATION,
        Hazard.HazardEnvelope(
            Hazard.SpatialBounds("cell-7/world", listOf(100L to 200L, 100L to 200L, 0L to 100L)),
            100L, Hazard.HazardWindow(10L, 900L),
        ),
    )
    hzExpectOk("present well-covered claim authorizes via the optional entry point") {
        Hazard.hazardAuthorizedOptional(claim, grant)
    }
}

// ==== 6. MALFORMED BODIES REJECTED (fail-closed, never partially valid) ==============================

private fun malformedBodiesRejectedRun() {
    // empty axes
    val bad = Hazard.SpatialBounds("f", emptyList())
    hzCheckBool("empty-axes SpatialBounds is not well-formed", bad.isWellFormed(), false)
    hzExpectThrows("empty-axes SpatialBounds.fromValue rejected", "HazardMalformed") {
        Hazard.SpatialBounds.fromValue(bad.toValue())
    }

    // min > max
    val bad2 = Hazard.SpatialBounds("f", listOf(10L to -10L))
    hzCheckBool("min>max SpatialBounds is not well-formed", bad2.isWellFormed(), false)

    // non-NFC frame ('e' + combining acute, NFD not NFC)
    val bad3 = Hazard.SpatialBounds("é", listOf(0L to 1L))
    hzCheckBool("non-NFC frame SpatialBounds is not well-formed", bad3.isWellFormed(), false)

    // wrong shape entirely (not a map)
    hzExpectThrows("non-map HazardClaim.fromValue rejected", "HazardMalformed") {
        Hazard.HazardClaim.fromValue(Cbor.U(0))
    }

    // class present, envelope missing
    val partial = Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.U(1))))
    hzExpectThrows("class-only body rejected", "HazardMalformed") {
        Hazard.HazardClaim.fromValue(partial)
    }

    // an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
    // normalized -- see Hazard.hazardBodyFromValue's doc comment.
    val goodEnv = Hazard.HazardEnvelope(Hazard.SpatialBounds("f", listOf(0L to 1L)), 1L, Hazard.HazardWindow(0L, 1L))
    val outOfRange = Cbor.M(listOf(
        Cbor.Pair(Cbor.U(1), Cbor.U(99)),
        Cbor.Pair(Cbor.U(2), goodEnv.toValue()),
    ))
    hzExpectThrows("out-of-range class on the wire rejected (not normalized)", "HazardMalformed") {
        Hazard.HazardClaim.fromValue(outOfRange)
    }
}

// ==== 7. CONTAINMENT TRUTH TABLES (independent of the oracle file, direct assertions) ================

private fun spatialContainedTruthTableRun() {
    val grant = Hazard.SpatialBounds("f", listOf(0L to 100L, 0L to 100L))
    // fully inside -> contained
    val inside = Hazard.SpatialBounds("f", listOf(10L to 90L, 10L to 90L))
    hzCheckBool("fully-inside contained", Hazard.spatialContained(inside, grant), true)
    // equal bounds -> contained (closed interval)
    val equal = Hazard.SpatialBounds("f", listOf(0L to 100L, 0L to 100L))
    hzCheckBool("equal-bounds contained (closed interval)", Hazard.spatialContained(equal, grant), true)
    // one axis pokes outside -> not contained
    val outside = Hazard.SpatialBounds("f", listOf(10L to 90L, 10L to 101L))
    hzCheckBool("one-axis-outside not contained", Hazard.spatialContained(outside, grant), false)
    // different frame -> never contained regardless of numeric bounds
    val wrongFrame = Hazard.SpatialBounds("g", listOf(10L to 90L, 10L to 90L))
    hzCheckBool("different-frame never contained", Hazard.spatialContained(wrongFrame, grant), false)
    // fewer axes -> never contained
    val fewer = Hazard.SpatialBounds("f", listOf(10L to 90L))
    hzCheckBool("fewer-axes never contained", Hazard.spatialContained(fewer, grant), false)
}

private fun envelopeContainedWindowAndSpeedRun() {
    fun env(lo: Long, hi: Long, speed: Long, nb: Long, na: Long) =
        Hazard.HazardEnvelope(Hazard.SpatialBounds("f", listOf(lo to hi)), speed, Hazard.HazardWindow(nb, na))

    val grant = env(0, 100, 500, 100, 900)
    val ok = env(0, 100, 500, 100, 900) // exact edges, closed interval
    hzCheckBool("exact-edges envelope contained", Hazard.envelopeContained(ok, grant), true)
    val speedOver = env(0, 100, 501, 100, 900)
    hzCheckBool("speed-over-bound not contained", Hazard.envelopeContained(speedOver, grant), false)
    val startsEarly = env(0, 100, 500, 99, 900)
    hzCheckBool("window-starts-early not contained", Hazard.envelopeContained(startsEarly, grant), false)
    val endsLate = env(0, 100, 500, 100, 901)
    hzCheckBool("window-ends-late not contained", Hazard.envelopeContained(endsLate, grant), false)
}

fun main() {
    println("HazardKatTest (Kotlin) -- Manufacturing Add-ons Component F (naalp-hazard)")
    fromCodeFailClosedRun()
    bytesAndRoundTripRun()
    coverageMatchesOracleRun()
    absentClaimDeniesWithDistinctErrorRun()
    malformedBodiesRejectedRun()
    spatialContainedTruthTableRun()
    envelopeContainedWindowAndSpeedRun()
    println(if (hzFails == 0) "HazardKatTest: PASS" else "HazardKatTest: FAIL ($hzFails)")
    if (hzFails != 0) kotlin.system.exitProcess(1)
}
