// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4)
 * known-answer tests for the Kotlin SDK, graded against the independent oracle
 * (tools/producing_boundary_oracle.py -> vectors/producing_boundary/cases.json), i.e.
 * Kotlin == Go == Rust == Python == oracle.
 *
 * Five properties, mirroring impl/go/envelope/producing_boundary_test.go and
 * impl/python/tests/test_producing_boundary.py, all mutation-surviving:
 *  1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body bytes;
 *     a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and the parsed
 *     disclosure (present/kind/boundary/reporting) matches. Non-canonical sub-map bytes are rejected
 *     NonCanonical at the codec.
 *  2. UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a different
 *     boundary into a signed object (keeping its id + signature) is rejected.
 *  3. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
 *     reporting-boundary under observed (an observer relays from no one).
 *  4. MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED disclosure
 *     (reporting under observed) in the non-critical ext map still verifies and is NOT surfaced.
 *  5. CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is UnknownCriticalExt.
 *
 * Vector loading is regex/scan-based (mirrors AudienceKat.kt), string-aware so embedded `{`/`}`/`[`/`]`
 * inside JSON string values (e.g. the corpus "note" fields) never desynchronize the object/array scan.
 *
 * Run (main()-driven, no test framework): compile the SDK sources plus this file into a jar, then
 *   java -cp "pb-kat.jar;<bcprov.jar>" sh.bubblefish.naalp.ProducingBoundaryKatTestKt
 */

private val PB_SEED = ByteArray(32) { it.toByte() } // a LOCAL test signing seed -- the verdict is a
                                                     // sign+verify round-trip, not a reproduction of
                                                     // the oracle's signature.
private const val PB_ALG = Cose.ALG_MLDSA65
private const val PB_X_HEX = "424f554e444152595f58"
private const val PB_Y_HEX = "4f524947494e5f59"

// the producing-boundary value sub-map WIRE keys (§2.5.4), used to build ext/cext DIRECTLY so the test
// grades the impl against the oracle's independent wire layout, not the impl's own private constants.
private const val PB_K_BOUNDARY = 1L
private const val PB_K_KIND = 2L
private const val PB_K_REPORTING = 3L

private val pbKindOk = Envelope.KindValidator { c, k -> c == 4L && k == 2L }

private class PBFailure(msg: String) : RuntimeException(msg)

// --- minimal, string-aware JSON scanning (regex per field, brace/bracket-depth splitting) ----------

/** Find the balanced `{...}` object following `"key":` in [s], or null if the value is JSON `null` or
 *  absent. String-aware: braces inside quoted string values (e.g. a "note" field) do not desync depth. */
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

/** Find the balanced `[...]` array following `"key":` in [s] and split it into its top-level `{...}`
 *  object substrings. Empty when the key is absent or the array is empty. String-aware, like
 *  [objectField]. */
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

/** Split the interior of a JSON array (no outer brackets) into its top-level `{...}` object
 *  substrings, string-aware so a `{`/`}` inside a quoted value never desyncs the depth count. */
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
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(null|\"[^\"]*\"|[-\\w]+)").find(s) ?: return null
    val raw = m.groupValues[1]
    if (raw == "null") return null
    return if (raw.startsWith("\"")) raw.substring(1, raw.length - 1) else raw
}

private fun strField(s: String, key: String): String? = nullableField(s, key)
private fun longField(s: String, key: String): Long? = nullableField(s, key)?.toLong()
private fun boolField(s: String, key: String): Boolean = nullableField(s, key) == "true"

// --- corpus model -------------------------------------------------------------------------------

private class PBCase(
    val name: String,
    val placement: String,
    val boundaryHex: String?,
    val kind: Long?,
    val reportingHex: String?,
    val present: Boolean,
    val surfacedKind: Long?,
    val surfacedBoundaryHex: String?,
    val surfacedReportingHex: String?,
    val bodyNoIdHex: String,
    val contentIdHex: String,
    val fullHex: String,
    val expect: String,
)

private class PBNegative(val name: String, val payloadHex: String, val expect: String)

private class PBCorpus(
    val producingBoundaryKey: Long,
    val baseKind: Long,
    val baseChannel: Long,
    val baseTier: Long,
    val baseSignerHex: String,
    val baseCreated: Long,
    val baseEffect: Long,
    val baseProfile: Long,
    val baseBodyStr: String,
    val cases: List<PBCase>,
    val negatives: List<PBNegative>,
)

private fun parseCase(o: String): PBCase {
    val present = boolField(o, "present")
    var surfacedKind: Long? = null
    var surfacedBoundaryHex: String? = null
    var surfacedReportingHex: String? = null
    if (present) {
        val surfaced = objectField(o, "surfaced")
            ?: throw PBFailure("case marks present but carries no surfaced disclosure")
        surfacedKind = longField(surfaced, "kind")
        surfacedBoundaryHex = strField(surfaced, "boundary_hex")
        surfacedReportingHex = nullableField(surfaced, "reporting_hex")
    }
    return PBCase(
        name = strField(o, "name") ?: throw PBFailure("case missing name"),
        placement = strField(o, "placement") ?: throw PBFailure("case missing placement"),
        boundaryHex = nullableField(o, "boundary_hex"),
        kind = longField(o, "kind"),
        reportingHex = nullableField(o, "reporting_hex"),
        present = present,
        surfacedKind = surfacedKind,
        surfacedBoundaryHex = surfacedBoundaryHex,
        surfacedReportingHex = surfacedReportingHex,
        bodyNoIdHex = strField(o, "body_no_id_hex") ?: throw PBFailure("case missing body_no_id_hex"),
        contentIdHex = strField(o, "content_id_hex") ?: throw PBFailure("case missing content_id_hex"),
        fullHex = strField(o, "full_hex") ?: throw PBFailure("case missing full_hex"),
        expect = strField(o, "expect") ?: throw PBFailure("case missing expect"),
    )
}

private fun parseNegative(o: String): PBNegative = PBNegative(
    name = strField(o, "name") ?: throw PBFailure("negative missing name"),
    payloadHex = strField(o, "payload_hex") ?: throw PBFailure("negative missing payload_hex"),
    expect = strField(o, "expect") ?: throw PBFailure("negative missing expect"),
)

/** Walk up from the working directory to find the committed producing_boundary vector, if present. */
private fun findVector(): File? {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: return null
        val p = File(cur, "vectors/producing_boundary/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    return null
}

private fun loadCorpus(): PBCorpus? {
    val f = findVector() ?: return null
    val json = f.readText(Charsets.UTF_8)
    val key = longField(json, "producing_boundary_key") ?: throw PBFailure("producing_boundary_key missing")
    val base = objectField(json, "base_object") ?: throw PBFailure("base_object missing")
    return PBCorpus(
        producingBoundaryKey = key,
        baseKind = longField(base, "kind") ?: throw PBFailure("base_object.kind missing"),
        baseChannel = longField(base, "channel") ?: throw PBFailure("base_object.channel missing"),
        baseTier = longField(base, "tier") ?: throw PBFailure("base_object.tier missing"),
        baseSignerHex = strField(base, "signer_hex") ?: throw PBFailure("base_object.signer_hex missing"),
        baseCreated = longField(base, "created") ?: throw PBFailure("base_object.created missing"),
        baseEffect = longField(base, "effect") ?: throw PBFailure("base_object.effect missing"),
        baseProfile = longField(base, "profile") ?: throw PBFailure("base_object.profile missing"),
        baseBodyStr = strField(base, "body_str") ?: throw PBFailure("base_object.body_str missing"),
        cases = arrayField(json, "cases").map(::parseCase),
        negatives = arrayField(json, "negatives").map(::parseNegative),
    )
}

private fun baseObject(c: PBCorpus): Envelope.Object = Envelope.Object(
    kind = c.baseKind, channel = c.baseChannel, tier = c.baseTier,
    signer = Hex.decode(c.baseSignerHex), created = c.baseCreated, effect = c.baseEffect,
    profile = c.baseProfile, body = Cbor.T(c.baseBodyStr),
)

/** Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields (the ONLY variable per
 *  case), reproducing the oracle bytes for well-formed AND malformed values -- the malformed cases
 *  cannot be built via [Envelope.setProducingBoundary] by design, so they are constructed here. */
private fun applyPlacement(o: Envelope.Object, tc: PBCase) {
    if (tc.placement == "absent") return
    val sub = ArrayList<Cbor.Pair>(3)
    val bh = tc.boundaryHex
    if (bh != null) sub.add(Cbor.Pair(Cbor.U(PB_K_BOUNDARY), Cbor.B(Hex.decode(bh))))
    val kd = tc.kind
    if (kd != null) sub.add(Cbor.Pair(Cbor.U(PB_K_KIND), Cbor.U(kd)))
    val rh = tc.reportingHex
    if (rh != null) sub.add(Cbor.Pair(Cbor.U(PB_K_REPORTING), Cbor.B(Hex.decode(rh))))
    val ext = Cbor.M(listOf(Cbor.Pair(Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), Cbor.M(sub))))
    when (tc.placement) {
        "ext" -> o.ext = ext
        "cext" -> o.cext = ext
        else -> throw PBFailure("unknown placement ${tc.placement}")
    }
}

// --- 1. MATCHES ORACLE -----------------------------------------------------------------------------

private fun testMatchesOracle(c: PBCorpus) {
    if (c.producingBoundaryKey != Envelope.PRODUCING_BOUNDARY_KEY) {
        throw PBFailure("corpus key ${c.producingBoundaryKey} != impl key ${Envelope.PRODUCING_BOUNDARY_KEY}")
    }
    val pk = Cose.mldsaKeygen("ML-DSA-65", PB_SEED)
    for (tc in c.cases) {
        val o = baseObject(c)
        applyPlacement(o, tc)
        val gotBodyNoId = Hex.encode(Cbor.encode(o.bodyMap(false)))
        if (gotBodyNoId != tc.bodyNoIdHex) {
            throw PBFailure("[${tc.name}] body-no-id\n got $gotBodyNoId\nwant ${tc.bodyNoIdHex}")
        }
        val cid = o.contentId()
        if (Hex.encode(cid) != tc.contentIdHex) {
            throw PBFailure("[${tc.name}] content-id\n got ${Hex.encode(cid)}\nwant ${tc.contentIdHex}")
        }
        o.id = cid
        val gotFull = Hex.encode(Cbor.encode(o.bodyMap(true)))
        if (gotFull != tc.fullHex) throw PBFailure("[${tc.name}] full-body\n got $gotFull\nwant ${tc.fullHex}")

        // verdict: sign for real + verify offline; assert accept vs the named error.
        val o2 = baseObject(c)
        applyPlacement(o2, tc)
        val signed = Envelope.sign(o2, PB_ALG, PB_SEED)
        if (tc.expect == "accept") {
            val got = Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, signed)
            val (pb, present) = Envelope.producingBoundary(got)
            if (present != tc.present) throw PBFailure("[${tc.name}] present: got $present want ${tc.present}")
            if (present) {
                if (pb == null) throw PBFailure("[${tc.name}] present but pb is null")
                if (pb.kind != tc.surfacedKind) {
                    throw PBFailure("[${tc.name}] kind: got ${pb.kind} want ${tc.surfacedKind}")
                }
                if (Hex.encode(pb.boundary) != tc.surfacedBoundaryHex) {
                    throw PBFailure("[${tc.name}] boundary: got ${Hex.encode(pb.boundary)} want ${tc.surfacedBoundaryHex}")
                }
                val wantReporting = tc.surfacedReportingHex ?: ""
                val gotReportingBytes = pb.reporting
                val gotReporting = if (gotReportingBytes != null) Hex.encode(gotReportingBytes) else ""
                if (gotReporting != wantReporting) {
                    throw PBFailure("[${tc.name}] reporting: got $gotReporting want $wantReporting")
                }
            }
        } else {
            var kind = ""
            try {
                Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, signed)
                throw PBFailure("[${tc.name}] expected ${tc.expect}, no exception thrown")
            } catch (e: NaalpException) {
                kind = e.kind
            }
            if (kind != tc.expect) throw PBFailure("[${tc.name}] expected ${tc.expect}, got $kind")
        }
        println("  ok  case ${tc.name}")
    }

    // non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
    val baseSigned = Envelope.sign(baseObject(c), PB_ALG, PB_SEED)
    val baseProt = Cose.parseSign1Raw(baseSigned)[0]
    for (neg in c.negatives) {
        val forged = Cose.coseSign1(PB_ALG, PB_SEED, baseProt, Hex.decode(neg.payloadHex))
        var kind = ""
        try {
            Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, forged)
            throw PBFailure("[negative ${neg.name}] expected ${neg.expect}, no exception thrown")
        } catch (e: NaalpException) {
            kind = e.kind
        }
        if (kind != neg.expect) throw PBFailure("[negative ${neg.name}] expected ${neg.expect}, got $kind")
        println("  ok  negative ${neg.name}")
    }
}

// --- 2. UNDER SIGNATURE -----------------------------------------------------------------------------

private fun testUnderSignature(c: PBCorpus) {
    val pk = Cose.mldsaKeygen("ML-DSA-65", PB_SEED)
    val o = baseObject(c)
    Envelope.setProducingBoundary(o, Envelope.ProducingBoundary(Hex.decode(PB_X_HEX), Envelope.PRODUCING_BOUNDARY_OBSERVED))
    val signed = Envelope.sign(o, PB_ALG, PB_SEED)
    val got = Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, signed)
    val (pb, present) = Envelope.producingBoundary(got)
    if (!present || pb == null || pb.kind != Envelope.PRODUCING_BOUNDARY_OBSERVED) {
        throw PBFailure("read-back: pb=$pb present=$present")
    }
    println("  ok  under-signature read-back")

    // tamper: change boundary, keep the original id, reuse the original signature (a splice).
    val tampered = baseObject(c)
    Envelope.setProducingBoundary(tampered, Envelope.ProducingBoundary(Hex.decode(PB_Y_HEX), Envelope.PRODUCING_BOUNDARY_OBSERVED))
    tampered.id = o.id // keep original content id -- a splice, not a re-sign
    val payload = Cbor.encode(tampered.bodyMap(true))
    val parts = Cose.parseSign1Raw(signed)
    val forged = Cose.assembleSign1Raw(parts[0], payload, parts[2])
    var threw = false
    try {
        Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, forged)
    } catch (e: NaalpException) {
        threw = true
    }
    if (!threw) throw PBFailure("tampered producing-boundary must be rejected (it is under signature), got accept")
    println("  ok  under-signature tamper rejected")
}

// --- 3. READER ROUND-TRIP ---------------------------------------------------------------------------

private fun testReaderRoundTrip(c: PBCorpus) {
    val o = baseObject(c)
    val (_, present0) = Envelope.producingBoundary(o)
    if (present0) throw PBFailure("fresh object must have no producing-boundary disclosure")
    val x = Hex.decode(PB_X_HEX)
    val y = Hex.decode(PB_Y_HEX)

    Envelope.setProducingBoundary(o, Envelope.ProducingBoundary(x, Envelope.PRODUCING_BOUNDARY_REPORTED, y))
    val (pb1, present1) = Envelope.producingBoundary(o)
    val pb1Reporting = pb1?.reporting
    if (!present1 || pb1 == null || pb1.kind != Envelope.PRODUCING_BOUNDARY_REPORTED ||
        !pb1.boundary.contentEquals(x) || pb1Reporting == null || !pb1Reporting.contentEquals(y)
    ) {
        throw PBFailure("reported disclosure round-trip wrong")
    }
    println("  ok  reported disclosure round-trip (boundary+reporting)")

    // the setter drops a reporting-boundary under observed: read-back has no reporting.
    Envelope.setProducingBoundary(o, Envelope.ProducingBoundary(x, Envelope.PRODUCING_BOUNDARY_OBSERVED, y))
    val (pb2, present2) = Envelope.producingBoundary(o)
    if (!present2 || pb2 == null || pb2.kind != Envelope.PRODUCING_BOUNDARY_OBSERVED || pb2.reporting != null) {
        throw PBFailure("observed disclosure must drop reporting")
    }
    println("  ok  setter drops reporting-boundary under observed")
}

// --- 4. MALFORMED IGNORED [MUTATION ANCHOR] ---------------------------------------------------------
//
// Dropping the reporting-under-observed check in Envelope.producingBoundary() flips present false->true
// and this test pass->fail; that check is the observer-relays-from-no-one invariant.

private fun testMalformedIgnored(c: PBCorpus) {
    val pk = Cose.mldsaKeygen("ML-DSA-65", PB_SEED)
    val o = baseObject(c)
    // malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
    o.ext = Cbor.M(
        listOf(
            Cbor.Pair(
                Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY),
                Cbor.M(
                    listOf(
                        Cbor.Pair(Cbor.U(PB_K_BOUNDARY), Cbor.B(Hex.decode(PB_X_HEX))),
                        Cbor.Pair(Cbor.U(PB_K_KIND), Cbor.U(Envelope.PRODUCING_BOUNDARY_OBSERVED)),
                        Cbor.Pair(Cbor.U(PB_K_REPORTING), Cbor.B(Hex.decode(PB_Y_HEX))),
                    )
                ),
            )
        )
    )
    val signed = Envelope.sign(o, PB_ALG, PB_SEED)
    val got = Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, signed) // must NOT throw (may-ignore)
    val (_, present) = Envelope.producingBoundary(got)
    if (present) throw PBFailure("a malformed disclosure (reporting under observed) must NOT be surfaced")
    println("  ok  malformed (reporting under observed) ignored, not surfaced")
}

// --- 5. CEXT REJECTED [MUTATION ANCHOR] -------------------------------------------------------------
//
// The disclosure placed in the CRITICAL cext map (field 12) is an unrecognized critical extension and
// the object is rejected UnknownCriticalExt. A disclosure must never masquerade as a must-understand
// gate.

private fun testCextRejected(c: PBCorpus) {
    val pk = Cose.mldsaKeygen("ML-DSA-65", PB_SEED)
    val o = baseObject(c)
    o.cext = Cbor.M(
        listOf(
            Cbor.Pair(
                Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY),
                Cbor.M(
                    listOf(
                        Cbor.Pair(Cbor.U(PB_K_BOUNDARY), Cbor.B(Hex.decode(PB_X_HEX))),
                        Cbor.Pair(Cbor.U(PB_K_KIND), Cbor.U(Envelope.PRODUCING_BOUNDARY_OBSERVED)),
                    )
                ),
            )
        )
    )
    val signed = Envelope.sign(o, PB_ALG, PB_SEED)
    try {
        Envelope.verify(Cose.PROFILE_PUBLIC, PB_ALG, pk, pbKindOk, signed)
        throw PBFailure("cext producing-boundary must be rejected UnknownCriticalExt, no exception thrown")
    } catch (e: NaalpException) {
        if (e.kind != "UnknownCriticalExt") {
            throw PBFailure("cext producing-boundary must be rejected UnknownCriticalExt, got ${e.kind}")
        }
    }
    println("  ok  cext producing-boundary rejected UnknownCriticalExt")
}

fun main() {
    println("ProducingBoundaryKatTest — NA-IETF-1 producing-boundary disclosure (ext key 15, §2.5.4)")
    val corpus = loadCorpus()
    if (corpus == null) {
        println("  ..  vectors/producing_boundary/cases.json not found; skipped")
        println("ProducingBoundaryKatTest: PASS (skipped -- committed vector not present)")
        return
    }
    testMatchesOracle(corpus)
    testUnderSignature(corpus)
    testReaderRoundTrip(corpus)
    testMalformedIgnored(corpus)
    testCextRejected(corpus)
    println("ProducingBoundaryKatTest: PASS")
}
