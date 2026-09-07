// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * T1.3 recheck (RECHECK_KEY=13, ext/cext §2.5.1) and T1.6 per-signer forward-only counter
 * (SIGNER_COUNTER_KEY=14, ext §2.5.2) + signer-duplication detection known-answer tests for the
 * Kotlin SDK, graded against the independent oracles (tools/recheck_oracle.py ->
 * vectors/recheck/cases.json, tools/signer_counter_oracle.py -> vectors/signer_counter/cases.json),
 * mirroring impl/go/envelope/envelope_test.go (T1.3) and impl/go/envelope/signer_counter_test.go
 * (T1.6), i.e. Kotlin == Go == Rust == oracle.
 *
 * Recheck properties (all mutation-surviving):
 *  1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id/content-id/full-body bytes; a
 *     real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; the parsed
 *     (id, present, critical) matches. Non-canonical cext bodies are rejected NonCanonical.
 *  2. REJECT PATH IS REAL [MUTATION ANCHOR] -- a CRITICAL recheck naming an UNKNOWN procedure id is
 *     rejected UnknownCriticalExt; the same unknown id NON-critical is ignored (accept); a KNOWN
 *     critical id accepts. Proves the reject is specific to unknown-under-critical.
 *  3. READER ROUND-TRIP -- setRecheck/recheck carry (id, critical); cext takes precedence over ext.
 *  4. IS-KNOWN-PROCEDURE BOUNDARIES -- the closed registry {1,2,3,4} true; {0,5} false.
 *
 * Signer-counter + detection properties (all mutation-surviving):
 *  5. MATCHES ORACLE -- byte parity + verdicts, as above.
 *  6. UNDER SIGNATURE -- the counter is folded into the SIGNER's signed body: splicing a different
 *     counter into a signed object (keeping its id + signature) is rejected.
 *  7. READER ROUND-TRIP -- the field is OPTIONAL; a present counter of value 0 reads back present.
 *  8. ABSENT VALIDATES [MUTATION ANCHOR] -- an object with no counter signs and verifies.
 *  9. DETECT MATCHES ORACLE -- detectSignerDuplication reproduces every scenario's findings
 *     (signer, counter, the SET of surfaced content ids).
 * 10. DETECT ONE-SEQUENCE NOT FLAGGED [MUTATION ANCHOR] -- one object alone, and an honest
 *     forward-only sequence, are never flagged (detection requires two conflicting sequences to
 *     physically meet).
 * 11. DETECT TWO-CONFLICTING FLAGGED -- two distinct objects, same signer, same counter, presented
 *     together -> flagged once, surfacing both content ids.
 * 12. DETECT FORWARD-ONLY-CONSISTENT / CROSS-SIGNER NOT FLAGGED -- different positions, or different
 *     signers at one position, are never flagged.
 *
 * Vector loading is regex/scan-based (mirrors ProducingBoundaryKatTest.kt / AudienceKatTest.kt), string-
 * aware so embedded `{`/`}`/`[`/`]` inside JSON string values (the corpus "note" fields) never
 * desynchronize the object/array scan. Numeric fields parse via Long.parseUnsignedLong so a counter
 * up to 2^64-1 (the counter_uint64_max case) decodes to the exact Cbor.U bit pattern without overflow.
 *
 * Run: compile the SDK sources plus this file, then
 *   java -cp "rsc-kat.jar;<bcprov.jar>" sh.bubblefish.naalp.RecheckSignerCounterKatTestKt
 */

private val RSK_SEED = ByteArray(32) { it.toByte() } // a LOCAL test signing seed -- the verdict is a
                                                      // sign+verify round-trip, not a reproduction of
                                                      // the oracle's signature.
private const val RSK_ALG = Cose.ALG_MLDSA65

private val rskKindOk = Envelope.KindValidator { c, k -> c == 4L && k == 2L }

private class RSFailure(msg: String) : RuntimeException(msg)

// --- minimal, string-aware JSON scanning (regex per field, brace/bracket-depth splitting) ----------
// Duplicated per-file (mirrors ProducingBoundaryKatTest.kt): each main()-driven KAT test file is
// compiled standalone, and Kotlin top-level `private` declarations are file-scoped, so there is no
// shared module to import these from without touching the build.

private fun objectField(s: String, key: String): String? {
    val idx = s.indexOf("\"$key\"")
    if (idx < 0) return null
    val after = s.substring(idx)
    val colon = after.indexOf(':')
    if (colon < 0) return null
    val rest = after.substring(colon + 1).trimStart()
    if (rest.startsWith("null")) return null
    if (!rest.startsWith("{")) return null
    var depth = 0
    var inString = false
    var escape = false
    for (i in rest.indices) {
        val c = rest[i]
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
            '{' -> depth++
            '}' -> {
                depth--
                if (depth == 0) return rest.substring(0, i + 1)
            }
        }
    }
    return null
}

private fun arrayField(s: String, key: String): List<String> {
    val idx = s.indexOf("\"$key\"")
    if (idx < 0) return emptyList()
    val after = s.substring(idx)
    val colon = after.indexOf(':')
    if (colon < 0) return emptyList()
    val rest = after.substring(colon + 1).trimStart()
    if (!rest.startsWith("[")) return emptyList()
    var depth = 0
    var inString = false
    var escape = false
    var end = -1
    for (i in rest.indices) {
        val c = rest[i]
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
            '[' -> depth++
            ']' -> {
                depth--
                if (depth == 0) {
                    end = i
                }
            }
        }
        if (end >= 0) break
    }
    if (end < 0) return emptyList()
    return splitJsonObjects(rest.substring(1, end))
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

/** `"key": null | "str" | bareToken` -> the raw string value, or null for JSON `null` / absent. */
private fun nullableField(s: String, key: String): String? {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(null|\"[^\"]*\"|-?[\\w]+)").find(s) ?: return null
    val raw = m.groupValues[1]
    if (raw == "null") return null
    return if (raw.startsWith("\"")) raw.substring(1, raw.length - 1) else raw
}

private fun strField(s: String, key: String): String? = nullableField(s, key)

/** An unsigned 64-bit-safe numeric field: parses via Long.parseUnsignedLong so a value up to
 *  2^64-1 decodes to the exact bit pattern Cbor.U carries, never overflowing/throwing the way a
 *  plain signed .toLong() would on e.g. "18446744073709551615". */
private fun uintField(s: String, key: String): Long? =
    nullableField(s, key)?.let { java.lang.Long.parseUnsignedLong(it) }

private fun boolField(s: String, key: String): Boolean = nullableField(s, key) == "true"

/** A flat JSON array of quoted (hex) strings -- no nested braces/brackets, so a plain regex scan
 *  over the array interior suffices (unlike [arrayField], which must depth-track `{...}` objects). */
private fun stringArrayField(s: String, key: String): List<String> {
    val idx = s.indexOf("\"$key\"")
    if (idx < 0) return emptyList()
    val after = s.substring(idx)
    val colon = after.indexOf(':')
    if (colon < 0) return emptyList()
    val rest = after.substring(colon + 1).trimStart()
    if (!rest.startsWith("[")) return emptyList()
    val end = rest.indexOf(']')
    if (end < 0) return emptyList()
    val inner = rest.substring(1, end)
    return Regex("\"([0-9a-fA-F]*)\"").findAll(inner).map { it.groupValues[1] }.toList()
}

private fun findVectorFile(relPath: String): File? {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: return null
        val p = File(cur, relPath)
        if (p.isFile) return p
        d = cur.parentFile
    }
    return null
}

// --- shared base-object builder --------------------------------------------------------------------

private fun buildBaseObject(
    kind: Long, channel: Long, tier: Long, signerHex: String, created: Long, effect: Long,
    causesHex: List<String>, profile: Long, bodyStr: String,
): Envelope.Object = Envelope.Object(
    kind = kind, channel = channel, tier = tier, signer = Hex.decode(signerHex),
    created = created, effect = effect, causes = causesHex.map { Hex.decode(it) },
    profile = profile, body = Cbor.T(bodyStr),
)

private class RSNegative(val name: String, val payloadHex: String, val expect: String)

private fun parseNegative(o: String): RSNegative = RSNegative(
    name = strField(o, "name") ?: throw RSFailure("negative missing name"),
    payloadHex = strField(o, "payload_hex") ?: throw RSFailure("negative missing payload_hex"),
    expect = strField(o, "expect") ?: throw RSFailure("negative missing expect"),
)

// --- T1.3 recheck corpus (vectors/recheck/cases.json) ------------------------------------------------

private class RecheckCorpus(
    val recheckKey: Long,
    val baseKind: Long, val baseChannel: Long, val baseTier: Long, val baseSignerHex: String,
    val baseCreated: Long, val baseEffect: Long, val baseCausesHex: List<String>, val baseProfile: Long,
    val baseBodyStr: String,
    val cases: List<RecheckCase>,
    val negatives: List<RSNegative>,
)

private class RecheckCase(
    val name: String, val placement: String, val critical: Boolean, val present: Boolean,
    val procedureId: Long?, val bodyNoIdHex: String, val contentIdHex: String, val fullHex: String,
    val expect: String,
)

private fun parseRecheckCase(o: String): RecheckCase = RecheckCase(
    name = strField(o, "name") ?: throw RSFailure("case missing name"),
    placement = strField(o, "placement") ?: throw RSFailure("case missing placement"),
    critical = boolField(o, "critical"),
    present = boolField(o, "present"),
    procedureId = uintField(o, "procedure_id"),
    bodyNoIdHex = strField(o, "body_no_id_hex") ?: throw RSFailure("case missing body_no_id_hex"),
    contentIdHex = strField(o, "content_id_hex") ?: throw RSFailure("case missing content_id_hex"),
    fullHex = strField(o, "full_hex") ?: throw RSFailure("case missing full_hex"),
    expect = strField(o, "expect") ?: throw RSFailure("case missing expect"),
)

private fun loadRecheckCorpus(): RecheckCorpus? {
    val f = findVectorFile("vectors/recheck/cases.json") ?: return null
    val json = f.readText(Charsets.UTF_8)
    val base = objectField(json, "base_object") ?: throw RSFailure("base_object missing")
    return RecheckCorpus(
        recheckKey = uintField(json, "recheck_key") ?: throw RSFailure("recheck_key missing"),
        baseKind = uintField(base, "kind") ?: throw RSFailure("base.kind missing"),
        baseChannel = uintField(base, "channel") ?: throw RSFailure("base.channel missing"),
        baseTier = uintField(base, "tier") ?: throw RSFailure("base.tier missing"),
        baseSignerHex = strField(base, "signer_hex") ?: throw RSFailure("base.signer_hex missing"),
        baseCreated = uintField(base, "created") ?: throw RSFailure("base.created missing"),
        baseEffect = uintField(base, "effect") ?: throw RSFailure("base.effect missing"),
        baseCausesHex = stringArrayField(base, "causes_hex"),
        baseProfile = uintField(base, "profile") ?: throw RSFailure("base.profile missing"),
        baseBodyStr = strField(base, "body_str") ?: throw RSFailure("base.body_str missing"),
        cases = arrayField(json, "cases").map(::parseRecheckCase),
        negatives = arrayField(json, "negatives").map(::parseNegative),
    )
}

private fun baseRecheckObject(c: RecheckCorpus): Envelope.Object = buildBaseObject(
    c.baseKind, c.baseChannel, c.baseTier, c.baseSignerHex, c.baseCreated, c.baseEffect,
    c.baseCausesHex, c.baseProfile, c.baseBodyStr,
)

/** Apply the case's recheck placement -- the ONLY variable across cases. */
private fun applyRecheckPlacement(o: Envelope.Object, tc: RecheckCase) {
    when (tc.placement) {
        "cext" -> Envelope.setRecheck(o, tc.procedureId ?: throw RSFailure("[${tc.name}] cext placement needs procedure_id"), true)
        "ext" -> Envelope.setRecheck(o, tc.procedureId ?: throw RSFailure("[${tc.name}] ext placement needs procedure_id"), false)
        "ext_empty" -> o.ext = Cbor.M(emptyList()) // present but empty (no recheck) -- distinct bytes from absent
        "absent" -> {} // no ext, no cext
        else -> throw RSFailure("unknown recheck placement ${tc.placement}")
    }
}

// --- 1. MATCHES ORACLE (recheck) ---------------------------------------------------------------------

private fun testRecheckMatchesOracle(c: RecheckCorpus) {
    if (c.recheckKey != Envelope.RECHECK_KEY) {
        throw RSFailure("recheck_key: corpus ${c.recheckKey} != impl ${Envelope.RECHECK_KEY}")
    }
    val pk = Cose.mldsaKeygen("ML-DSA-65", RSK_SEED)
    for (tc in c.cases) {
        val o = baseRecheckObject(c)
        applyRecheckPlacement(o, tc)
        val gotBodyNoId = Hex.encode(Cbor.encode(o.bodyMap(false)))
        if (gotBodyNoId != tc.bodyNoIdHex) throw RSFailure("[${tc.name}] body-no-id\n got $gotBodyNoId\nwant ${tc.bodyNoIdHex}")
        val cid = o.contentId()
        if (Hex.encode(cid) != tc.contentIdHex) throw RSFailure("[${tc.name}] content-id\n got ${Hex.encode(cid)}\nwant ${tc.contentIdHex}")
        o.id = cid
        val gotFull = Hex.encode(Cbor.encode(o.bodyMap(true)))
        if (gotFull != tc.fullHex) throw RSFailure("[${tc.name}] full-body\n got $gotFull\nwant ${tc.fullHex}")

        val o2 = baseRecheckObject(c)
        applyRecheckPlacement(o2, tc)
        val signed = Envelope.sign(o2, RSK_ALG, RSK_SEED)
        if (tc.expect == "accept") {
            val got = Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, signed)
            val (rid, present, critical) = Envelope.recheck(got)
            if (present != tc.present) throw RSFailure("[${tc.name}] Recheck present: got $present want ${tc.present}")
            if (present) {
                if (tc.procedureId == null || rid != tc.procedureId) throw RSFailure("[${tc.name}] Recheck id: got $rid want ${tc.procedureId}")
                if (critical != tc.critical) throw RSFailure("[${tc.name}] Recheck critical: got $critical want ${tc.critical}")
            }
        } else {
            var kind = ""
            try {
                Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, signed)
                throw RSFailure("[${tc.name}] expected ${tc.expect}, no exception thrown")
            } catch (e: NaalpException) {
                kind = e.kind
            }
            if (kind != tc.expect) throw RSFailure("[${tc.name}] expected ${tc.expect}, got $kind")
        }
        println("  ok  recheck case ${tc.name}")
    }

    // non-canonical recheck bodies (keys out of order) are rejected at the CBOR layer.
    val baseSigned = Envelope.sign(baseRecheckObject(c), RSK_ALG, RSK_SEED)
    val baseProt = Cose.parseSign1Raw(baseSigned)[0]
    for (neg in c.negatives) {
        val forged = Cose.coseSign1(RSK_ALG, RSK_SEED, baseProt, Hex.decode(neg.payloadHex))
        var kind = ""
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, forged)
            throw RSFailure("[negative ${neg.name}] expected ${neg.expect}, no exception thrown")
        } catch (e: NaalpException) {
            kind = e.kind
        }
        if (kind != neg.expect) throw RSFailure("[negative ${neg.name}] expected ${neg.expect}, got $kind")
        println("  ok  recheck negative ${neg.name}")
    }
}

// --- 2. REJECT PATH IS REAL [MUTATION ANCHOR] (recheck) ----------------------------------------------
//
// A CRITICAL recheck naming an UNKNOWN procedure id MUST be rejected UnknownCriticalExt. If the
// verify()-side critical-extension check for RECHECK_KEY is mutated to accept unconditionally, this
// test flips pass->fail. A known critical procedure and a non-critical unknown procedure both verify,
// proving the reject is specific to unknown-under-critical and not a blanket denial.

private fun testRecheckRejectPathIsReal(c: RecheckCorpus) {
    val pk = Cose.mldsaKeygen("ML-DSA-65", RSK_SEED)

    val criticalUnknown = baseRecheckObject(c)
    Envelope.setRecheck(criticalUnknown, 99L, true) // unknown id, critical
    val su = Envelope.sign(criticalUnknown, RSK_ALG, RSK_SEED)
    try {
        Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, su)
        throw RSFailure("critical unknown recheck must be rejected, got accept")
    } catch (e: NaalpException) {
        if (e.kind != "UnknownCriticalExt") throw RSFailure("want UnknownCriticalExt, got ${e.kind}")
    }

    val criticalKnown = baseRecheckObject(c)
    Envelope.setRecheck(criticalKnown, Envelope.RECHECK_WALK_CAUSES, true) // known id, critical
    val sk = Envelope.sign(criticalKnown, RSK_ALG, RSK_SEED)
    Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, sk) // must not throw

    val nonCritUnknown = baseRecheckObject(c)
    Envelope.setRecheck(nonCritUnknown, 99L, false) // unknown id, non-critical -> ignored
    val sn = Envelope.sign(nonCritUnknown, RSK_ALG, RSK_SEED)
    Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, sn) // must not throw

    println("  ok  recheck reject-path is real [MUTATION ANCHOR] (critical-unknown rejected; critical-known + noncritical-unknown accepted)")
}

// --- 3. READER ROUND-TRIP (recheck) -------------------------------------------------------------------

private fun testRecheckReaderRoundTrip(c: RecheckCorpus) {
    val o = baseRecheckObject(c)
    val (_, present0, _) = Envelope.recheck(o)
    if (present0) throw RSFailure("fresh object must have no recheck")

    Envelope.setRecheck(o, Envelope.RECHECK_VERIFY_COSE_SIGN1, false)
    val (id1, present1, critical1) = Envelope.recheck(o)
    if (!present1 || id1 != Envelope.RECHECK_VERIFY_COSE_SIGN1 || critical1) {
        throw RSFailure("non-critical recheck read back wrong: id=$id1 present=$present1 critical=$critical1")
    }

    Envelope.setRecheck(o, Envelope.RECHECK_REPLAY_CONSUME_CHECK, true) // critical wins over the ext entry
    val (id2, present2, critical2) = Envelope.recheck(o)
    if (!present2 || id2 != Envelope.RECHECK_REPLAY_CONSUME_CHECK || !critical2) {
        throw RSFailure("critical recheck must take precedence: id=$id2 present=$present2 critical=$critical2")
    }
    println("  ok  recheck reader round-trip (optional + cext precedence over ext)")
}

// --- 4. IS-KNOWN-PROCEDURE BOUNDARIES (recheck) ---------------------------------------------------

private fun testIsKnownRecheckProcedureBoundaries() {
    for (id in 1L..4L) {
        if (!Envelope.isKnownRecheckProcedure(id)) throw RSFailure("isKnownRecheckProcedure($id) must be true")
    }
    for (id in listOf(0L, 5L)) {
        if (Envelope.isKnownRecheckProcedure(id)) throw RSFailure("isKnownRecheckProcedure($id) must be false")
    }
    println("  ok  isKnownRecheckProcedure boundaries (1..4 true, 0 and 5 false; closed registry)")
}

// --- T1.6 signer-counter + detection corpus (vectors/signer_counter/cases.json) -----------------------

private class CounterCorpus(
    val counterKey: Long,
    val baseKind: Long, val baseChannel: Long, val baseTier: Long, val baseSignerHex: String,
    val baseCreated: Long, val baseEffect: Long, val baseCausesHex: List<String>, val baseProfile: Long,
    val baseBodyStr: String,
    val cases: List<CounterCase>,
    val negatives: List<RSNegative>,
    val scenarios: List<DetectionScenario>,
)

private class CounterCase(
    val name: String, val placement: String, val present: Boolean, val counter: Long?,
    val signerHex: String, val bodyStr: String,
    val bodyNoIdHex: String, val contentIdHex: String, val fullHex: String, val expect: String,
)

private class DetectionObject(val signerHex: String, val counter: Long?, val bodyStr: String, val contentIdHex: String)
private class DetectionExpect(val signerHex: String, val counter: Long, val idsHex: List<String>)
private class DetectionScenario(val name: String, val objects: List<DetectionObject>, val expect: List<DetectionExpect>)

private fun parseCounterCase(o: String): CounterCase = CounterCase(
    name = strField(o, "name") ?: throw RSFailure("case missing name"),
    placement = strField(o, "placement") ?: throw RSFailure("case missing placement"),
    present = boolField(o, "present"),
    counter = uintField(o, "counter"),
    signerHex = strField(o, "signer_hex") ?: "",
    bodyStr = strField(o, "body_str") ?: "",
    bodyNoIdHex = strField(o, "body_no_id_hex") ?: throw RSFailure("case missing body_no_id_hex"),
    contentIdHex = strField(o, "content_id_hex") ?: throw RSFailure("case missing content_id_hex"),
    fullHex = strField(o, "full_hex") ?: throw RSFailure("case missing full_hex"),
    expect = strField(o, "expect") ?: throw RSFailure("case missing expect"),
)

private fun parseDetectionObject(o: String): DetectionObject = DetectionObject(
    signerHex = strField(o, "signer_hex") ?: throw RSFailure("detection object missing signer_hex"),
    counter = uintField(o, "counter"),
    bodyStr = strField(o, "body_str") ?: throw RSFailure("detection object missing body_str"),
    contentIdHex = strField(o, "content_id_hex") ?: throw RSFailure("detection object missing content_id_hex"),
)

private fun parseDetectionExpect(o: String): DetectionExpect = DetectionExpect(
    signerHex = strField(o, "signer_hex") ?: throw RSFailure("detection expect missing signer_hex"),
    counter = uintField(o, "counter") ?: throw RSFailure("detection expect missing counter"),
    idsHex = stringArrayField(o, "ids_hex"),
)

private fun parseDetectionScenario(o: String): DetectionScenario = DetectionScenario(
    name = strField(o, "name") ?: throw RSFailure("scenario missing name"),
    objects = arrayField(o, "objects").map(::parseDetectionObject),
    expect = arrayField(o, "expect").map(::parseDetectionExpect),
)

private fun loadCounterCorpus(): CounterCorpus? {
    val f = findVectorFile("vectors/signer_counter/cases.json") ?: return null
    val json = f.readText(Charsets.UTF_8)
    val base = objectField(json, "base_object") ?: throw RSFailure("base_object missing")
    val detection = objectField(json, "detection") ?: throw RSFailure("detection missing")
    return CounterCorpus(
        counterKey = uintField(json, "counter_key") ?: throw RSFailure("counter_key missing"),
        baseKind = uintField(base, "kind") ?: throw RSFailure("base.kind missing"),
        baseChannel = uintField(base, "channel") ?: throw RSFailure("base.channel missing"),
        baseTier = uintField(base, "tier") ?: throw RSFailure("base.tier missing"),
        baseSignerHex = strField(base, "signer_hex") ?: throw RSFailure("base.signer_hex missing"),
        baseCreated = uintField(base, "created") ?: throw RSFailure("base.created missing"),
        baseEffect = uintField(base, "effect") ?: throw RSFailure("base.effect missing"),
        baseCausesHex = stringArrayField(base, "causes_hex"),
        baseProfile = uintField(base, "profile") ?: throw RSFailure("base.profile missing"),
        baseBodyStr = strField(base, "body_str") ?: throw RSFailure("base.body_str missing"),
        cases = arrayField(json, "cases").map(::parseCounterCase),
        negatives = arrayField(json, "negatives").map(::parseNegative),
        scenarios = arrayField(detection, "scenarios").map(::parseDetectionScenario),
    )
}

/** [signerHexOverride]/[bodyStrOverride] override the corpus base when non-empty (the ONLY variable
 *  across cases/scenario-objects), mirroring impl/go's baseCounterObject. */
private fun baseCounterObject(c: CounterCorpus, signerHexOverride: String, bodyStrOverride: String): Envelope.Object {
    val sh = if (signerHexOverride.isNotEmpty()) signerHexOverride else c.baseSignerHex
    val bs = if (bodyStrOverride.isNotEmpty()) bodyStrOverride else c.baseBodyStr
    return buildBaseObject(c.baseKind, c.baseChannel, c.baseTier, sh, c.baseCreated, c.baseEffect, c.baseCausesHex, c.baseProfile, bs)
}

/** Apply the case's counter placement -- the ONLY variable per case. */
private fun applyCounterPlacement(o: Envelope.Object, tc: CounterCase) {
    when (tc.placement) {
        "ext" -> Envelope.setSignerCounter(o, tc.counter ?: throw RSFailure("[${tc.name}] ext placement needs counter"))
        "cext" -> { // the counter placed in the CRITICAL map is an unrecognized critical extension.
            val v = tc.counter ?: throw RSFailure("[${tc.name}] cext placement needs counter")
            o.cext = Cbor.M(listOf(Cbor.Pair(Cbor.U(Envelope.SIGNER_COUNTER_KEY), Cbor.U(v))))
        }
        "ext_empty" -> o.ext = Cbor.M(emptyList()) // present but empty (no counter) -- distinct bytes from absent
        "absent" -> {} // no ext, no cext
        else -> throw RSFailure("unknown counter placement ${tc.placement}")
    }
}

// --- 5. MATCHES ORACLE (signer-counter) ----------------------------------------------------------

private fun testCounterMatchesOracle(c: CounterCorpus) {
    if (c.counterKey != Envelope.SIGNER_COUNTER_KEY) {
        throw RSFailure("counter_key: corpus ${c.counterKey} != impl ${Envelope.SIGNER_COUNTER_KEY}")
    }
    val pk = Cose.mldsaKeygen("ML-DSA-65", RSK_SEED)
    for (tc in c.cases) {
        val o = baseCounterObject(c, tc.signerHex, tc.bodyStr)
        applyCounterPlacement(o, tc)
        val gotBodyNoId = Hex.encode(Cbor.encode(o.bodyMap(false)))
        if (gotBodyNoId != tc.bodyNoIdHex) throw RSFailure("[${tc.name}] body-no-id\n got $gotBodyNoId\nwant ${tc.bodyNoIdHex}")
        val cid = o.contentId()
        if (Hex.encode(cid) != tc.contentIdHex) throw RSFailure("[${tc.name}] content-id\n got ${Hex.encode(cid)}\nwant ${tc.contentIdHex}")
        o.id = cid
        val gotFull = Hex.encode(Cbor.encode(o.bodyMap(true)))
        if (gotFull != tc.fullHex) throw RSFailure("[${tc.name}] full-body\n got $gotFull\nwant ${tc.fullHex}")

        val o2 = baseCounterObject(c, tc.signerHex, tc.bodyStr)
        applyCounterPlacement(o2, tc)
        val signed = Envelope.sign(o2, RSK_ALG, RSK_SEED)
        if (tc.expect == "accept") {
            val got = Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, signed)
            val (seq, present) = Envelope.signerCounter(got)
            if (present != tc.present) throw RSFailure("[${tc.name}] SignerCounter present: got $present want ${tc.present}")
            if (present) {
                if (tc.counter == null || seq != tc.counter) throw RSFailure("[${tc.name}] SignerCounter value: got $seq want ${tc.counter}")
            }
        } else {
            var kind = ""
            try {
                Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, signed)
                throw RSFailure("[${tc.name}] expected ${tc.expect}, no exception thrown")
            } catch (e: NaalpException) {
                kind = e.kind
            }
            if (kind != tc.expect) throw RSFailure("[${tc.name}] expected ${tc.expect}, got $kind")
        }
        println("  ok  counter case ${tc.name}")
    }

    // non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
    val baseSigned = Envelope.sign(baseCounterObject(c, "", ""), RSK_ALG, RSK_SEED)
    val baseProt = Cose.parseSign1Raw(baseSigned)[0]
    for (neg in c.negatives) {
        val forged = Cose.coseSign1(RSK_ALG, RSK_SEED, baseProt, Hex.decode(neg.payloadHex))
        var kind = ""
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, forged)
            throw RSFailure("[negative ${neg.name}] expected ${neg.expect}, no exception thrown")
        } catch (e: NaalpException) {
            kind = e.kind
        }
        if (kind != neg.expect) throw RSFailure("[negative ${neg.name}] expected ${neg.expect}, got $kind")
        println("  ok  counter negative ${neg.name}")
    }
}

// --- 6. UNDER SIGNATURE (signer-counter) --------------------------------------------------------------

private fun testCounterUnderSignature(c: CounterCorpus) {
    val pk = Cose.mldsaKeygen("ML-DSA-65", RSK_SEED)
    val o = baseCounterObject(c, "", "")
    Envelope.setSignerCounter(o, 5L)
    val signed = Envelope.sign(o, RSK_ALG, RSK_SEED)
    val got = Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, signed)
    val (seq, present) = Envelope.signerCounter(got)
    if (!present || seq != 5L) throw RSFailure("counter read-back: got ($seq,$present) want (5,true)")

    // tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; the object must be
    // rejected (the content id no longer matches the signed body / the signature no longer covers it).
    val tampered = baseCounterObject(c, "", "")
    Envelope.setSignerCounter(tampered, 6L)
    tampered.id = o.id // keep the original (counter=5) content id -- a splice, not a re-sign
    val payload = Cbor.encode(tampered.bodyMap(true))
    val parts = Cose.parseSign1Raw(signed)
    // reuse the ORIGINAL signature bytes from the counter=5 object (a real forgery attempt).
    val forged = Cose.assembleSign1Raw(parts[0], payload, parts[2])
    var threw = false
    try {
        Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, forged)
    } catch (e: NaalpException) {
        threw = true
    }
    if (!threw) throw RSFailure("tampered counter must be rejected (the counter is under signature), got accept")
    println("  ok  counter under-signature (read-back + tamper rejected)")
}

// --- 7. READER ROUND-TRIP (signer-counter) --------------------------------------------------------

private fun testCounterReaderRoundTrip(c: CounterCorpus) {
    val o = baseCounterObject(c, "", "")
    val (_, present0) = Envelope.signerCounter(o)
    if (present0) throw RSFailure("fresh object must have no counter")
    Envelope.setSignerCounter(o, 42L)
    val (seq1, present1) = Envelope.signerCounter(o)
    if (!present1 || seq1 != 42L) throw RSFailure("counter read back wrong: seq=$seq1 present=$present1")
    Envelope.setSignerCounter(o, 0L) // present with value zero
    val (seq2, present2) = Envelope.signerCounter(o)
    if (!present2 || seq2 != 0L) throw RSFailure("present-zero counter must read back present: seq=$seq2 present=$present2")
    println("  ok  counter reader round-trip (optional + present-zero)")
}

// --- 8. ABSENT VALIDATES [MUTATION ANCHOR] (signer-counter) ------------------------------------------
//
// An object carrying NO counter Signs and Verifies. Making the field mandatory (e.g. adding a
// reject-if-absent check to verify()) flips this test pass->fail.

private fun testCounterAbsentValidates(c: CounterCorpus) {
    val pk = Cose.mldsaKeygen("ML-DSA-65", RSK_SEED)
    val o = baseCounterObject(c, "", "")
    val (_, present0) = Envelope.signerCounter(o)
    if (present0) throw RSFailure("object built without a counter must have none")
    val signed = Envelope.sign(o, RSK_ALG, RSK_SEED)
    val got = Envelope.verify(Cose.PROFILE_PUBLIC, RSK_ALG, pk, rskKindOk, signed)
    val (_, present1) = Envelope.signerCounter(got)
    if (present1) throw RSFailure("verified object must report no counter")
    println("  ok  counter absent validates (field is OPTIONAL) [MUTATION ANCHOR]")
}

// --- 9. DETECT MATCHES ORACLE ------------------------------------------------------------------------

/** Rebuild a scenario's presented objects from their logical fields, cross-checking each recomputed
 *  content id against the oracle's. */
private fun buildScenarioObjects(c: CounterCorpus, objs: List<DetectionObject>): List<Envelope.Object> {
    val out = ArrayList<Envelope.Object>(objs.size)
    for (ro in objs) {
        val o = baseCounterObject(c, ro.signerHex, ro.bodyStr)
        if (ro.counter != null) Envelope.setSignerCounter(o, ro.counter)
        val id = o.contentId()
        if (Hex.encode(id) != ro.contentIdHex) {
            throw RSFailure("scenario object content-id\n got ${Hex.encode(id)}\nwant ${ro.contentIdHex}")
        }
        out.add(o)
    }
    return out
}

private fun testDetectMatchesOracle(c: CounterCorpus) {
    for (sc in c.scenarios) {
        val objs = buildScenarioObjects(c, sc.objects)
        val findings = Envelope.detectSignerDuplication(objs)
        if (findings.size != sc.expect.size) {
            throw RSFailure("[${sc.name}] findings count: got ${findings.size} want ${sc.expect.size}")
        }
        for (i in sc.expect.indices) {
            val want = sc.expect[i]
            val got = findings[i]
            if (Hex.encode(got.signer) != want.signerHex) {
                throw RSFailure("[${sc.name}] finding $i signer: got ${Hex.encode(got.signer)} want ${want.signerHex}")
            }
            if (got.counter != want.counter) {
                throw RSFailure("[${sc.name}] finding $i counter: got ${got.counter} want ${want.counter}")
            }
            if (got.ids.size != want.idsHex.size) {
                throw RSFailure("[${sc.name}] finding $i ids count: got ${got.ids.size} want ${want.idsHex.size}")
            }
            for (j in want.idsHex.indices) {
                if (Hex.encode(got.ids[j]) != want.idsHex[j]) {
                    throw RSFailure("[${sc.name}] finding $i id $j: got ${Hex.encode(got.ids[j])} want ${want.idsHex[j]}")
                }
            }
        }
        println("  ok  detect scenario ${sc.name}")
    }
}

// --- 10. DETECT ONE-SEQUENCE NOT FLAGGED [MUTATION ANCHOR] -------------------------------------------
//
// A single sequence (one object per value) MUST NOT be flagged -- detection requires two conflicting
// sequences to physically meet. Relaxing the `idset.size < 2` guard in detectSignerDuplication to
// `< 1` (flag from one) flips this test pass->fail; that is the whole detection-not-prevention line.

private fun testDetectOneSequenceNotFlagged(c: CounterCorpus) {
    // one object alone at position 5.
    val one = baseCounterObject(c, "", "holder")
    Envelope.setSignerCounter(one, 5L)
    if (Envelope.detectSignerDuplication(listOf(one)).isNotEmpty()) {
        throw RSFailure("one sequence alone must not be flagged")
    }
    // a full honest forward-only sequence from one signer (1,2,3) is also one sequence -> not flagged.
    val seqObjs = ArrayList<Envelope.Object>()
    for ((i, body) in listOf("s1", "s2", "s3").withIndex()) {
        val o = baseCounterObject(c, "", body)
        Envelope.setSignerCounter(o, (i + 1).toLong())
        seqObjs.add(o)
    }
    if (Envelope.detectSignerDuplication(seqObjs).isNotEmpty()) {
        throw RSFailure("an honest forward-only sequence must not be flagged")
    }
    println("  ok  detect one-sequence / forward-only-honest not flagged [MUTATION ANCHOR]")
}

// --- 11. DETECT TWO-CONFLICTING FLAGGED ---------------------------------------------------------------
//
// Two DISTINCT objects, SAME signer id, SAME counter value, presented TOGETHER -> flagged once,
// surfacing BOTH content ids. This is the duplication fingerprint and it is only observable because
// both objects are present.

private fun testDetectTwoConflictingFlagged(c: CounterCorpus) {
    val holder = baseCounterObject(c, "", "holder")
    Envelope.setSignerCounter(holder, 5L)
    val thief = baseCounterObject(c, "", "thief")
    Envelope.setSignerCounter(thief, 5L)

    val f = Envelope.detectSignerDuplication(listOf(holder, thief))
    if (f.size != 1) throw RSFailure("two conflicting sequences must be flagged once, got ${f.size}")
    if (f[0].counter != 5L) throw RSFailure("finding counter: got ${f[0].counter} want 5")
    if (f[0].ids.size != 2) throw RSFailure("both conflicting content ids must be surfaced, got ${f[0].ids.size}")
    val hid = Hex.encode(holder.contentId())
    val tid = Hex.encode(thief.contentId())
    val surfaced = f[0].ids.map { Hex.encode(it) }.toSet()
    if (hid !in surfaced || tid !in surfaced) {
        throw RSFailure("the finding must surface both the holder's and the thief's content ids")
    }
    println("  ok  detect two-conflicting flagged (both content ids surfaced)")
}

// --- 12. DETECT FORWARD-ONLY-CONSISTENT / CROSS-SIGNER NOT FLAGGED -----------------------------------

private fun testDetectForwardOnlyConsistentNotFlagged(c: CounterCorpus) {
    val a5 = baseCounterObject(c, "", "holder")
    Envelope.setSignerCounter(a5, 5L)
    val a6 = baseCounterObject(c, "", "next")
    Envelope.setSignerCounter(a6, 6L)
    if (Envelope.detectSignerDuplication(listOf(a5, a6)).isNotEmpty()) {
        throw RSFailure("forward-only-consistent sequence must not be flagged")
    }

    // per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
    val b5 = baseCounterObject(c, "5349474e45525f42", "other") // "SIGNER_B"
    Envelope.setSignerCounter(b5, 5L)
    if (Envelope.detectSignerDuplication(listOf(a5, b5)).isNotEmpty()) {
        throw RSFailure("different signers at one value must not be flagged")
    }
    println("  ok  detect forward-only-consistent / cross-signer not flagged")
}

fun main() {
    println("RecheckSignerCounterKatTest -- T1.3 recheck (ext/cext key 13, §2.5.1) + T1.6 signer-counter (ext key 14, §2.5.2) + duplication detection")

    val rc = loadRecheckCorpus()
    if (rc == null) {
        println("  ..  vectors/recheck/cases.json not found; skipped")
    } else {
        testRecheckMatchesOracle(rc)
        testRecheckRejectPathIsReal(rc)
        testRecheckReaderRoundTrip(rc)
    }
    testIsKnownRecheckProcedureBoundaries()

    val cc = loadCounterCorpus()
    if (cc == null) {
        println("  ..  vectors/signer_counter/cases.json not found; skipped")
    } else {
        testCounterMatchesOracle(cc)
        testCounterUnderSignature(cc)
        testCounterReaderRoundTrip(cc)
        testCounterAbsentValidates(cc)
        testDetectMatchesOracle(cc)
        testDetectOneSequenceNotFlagged(cc)
        testDetectTwoConflictingFlagged(cc)
        testDetectForwardOnlyConsistentNotFlagged(cc)
    }

    println("RecheckSignerCounterKatTest: PASS")
}
