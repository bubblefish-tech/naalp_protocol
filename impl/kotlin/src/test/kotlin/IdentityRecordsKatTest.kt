// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * N-AALP C4 identity RECORD + THREAD surfaces (design.md §5.2/§5.3/§5.4/§5.5, R-1.4/R-5.2/R-5.3/
 * R-5.4) known-answer tests for the Kotlin SDK, graded against the independent oracle
 * (tools/identity_records_oracle.py -> vectors/identity_records/cases.json), i.e.
 * Kotlin == Go == Rust == oracle.
 *
 * The eleven RECORD + THREAD surfaces ported here (mirroring impl/go/identity/identity.go and
 * impl/rust/src/identity.rs identity_records_oracle_test.go/identity_records_matches_oracle tests):
 * RevocationRecord(+.bytes), VerifyRevocation, RevokedAt, ForeignLinkRecord(+.bytes),
 * VerifyForeignLink, RotationEvidence, Thread(+.attributable), ResolveThread.
 *
 * VerifyRevocation is SECURITY-CRITICAL and fail-closed (§5.3/§5.5): the signer id is recomputed
 * from the presented key and checked for membership in {record.key} UNION recoveryIds BEFORE the
 * signature is verified. MUTATION ANCHOR: "recovery_key_not_configured_reject" pins that an EMPTY
 * recoveryIds set admits only the revoked key itself -- dropping the membership guard (authorized =
 * true unconditionally) flips this case (and "wrong_key_reject") from SignerMismatch to accept.
 *
 * Vector loading is regex/scan-based (mirrors ProducingBoundaryKatTest.kt), string-aware so embedded
 * `{`/`}`/`[`/`]` inside JSON string values never desynchronize the object/array scan.
 *
 * Run (main()-driven, no test framework): compile the SDK sources plus this file into a jar, then
 *   java -cp "identity-records-kat.jar;<bcprov.jar>" sh.bubblefish.naalp.IdentityRecordsKatTestKt
 */

private class IRFailure(msg: String) : RuntimeException(msg)

// --- minimal, string-aware JSON scanning (regex per field, brace/bracket-depth splitting) ----------
// (mirrors ProducingBoundaryKatTest.kt's private helpers; private-to-file, no cross-file clash.)

/** Find the balanced `{...}` object following `"key":` in [s], or null if the value is JSON `null` or
 *  absent. String-aware: braces inside quoted string values do not desync depth. */
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
 *  object substrings. Empty when the key is absent or the array is empty. String-aware. */
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
 *  substrings, string-aware. */
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

/** `"key": ["a","b",...]` -> the string list; empty when absent/empty. Elements are plain (non-nested)
 *  quoted strings, so a simple string-aware bracket scan plus a string regex over the interior is
 *  sufficient (both `authorized_recovery_ids` and `chain` are flat string arrays). */
private fun stringArrayField(s: String, key: String): List<String> {
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
    var close = -1
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
                    close = i
                }
            }
        }
        if (close >= 0) break
    }
    if (close < 0) return emptyList()
    val body = rest.substring(1, close)
    val out = ArrayList<String>()
    for (m in Regex("\"((?:[^\"\\\\]|\\\\.)*)\"").findAll(body)) out.add(m.groupValues[1])
    return out
}

/** `"key": null | "str" | bareToken` -> the raw string value, or null for JSON `null` / absent. */
private fun nullableField(s: String, key: String): String? {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(null|\"[^\"]*\"|-?[\\w.]+)").find(s) ?: return null
    val raw = m.groupValues[1]
    if (raw == "null") return null
    return if (raw.startsWith("\"")) raw.substring(1, raw.length - 1) else raw
}

private fun strField(s: String, key: String): String? = nullableField(s, key)
private fun longField(s: String, key: String): Long? = nullableField(s, key)?.toLong()
private fun intField(s: String, key: String): Int? = nullableField(s, key)?.toInt()
private fun boolField(s: String, key: String): Boolean = nullableField(s, key) == "true"

/** Walk up from the working directory to find the committed identity_records vector, if present. */
private fun findVector(): File? {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: return null
        val p = File(cur, "vectors/identity_records/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    return null
}

private fun eq(what: String, got: Any?, want: Any?) {
    if (got != want) throw IRFailure("$what:\n  got  = $got\n  want = $want")
}

fun main() {
    println("IdentityRecordsKatTest — C4 identity RECORD + THREAD surfaces (§5.2-§5.5, R-1.4)")
    val f = findVector()
    if (f == null) {
        println("  ..  vectors/identity_records/cases.json not found; skipped")
        println("IdentityRecordsKatTest: PASS (skipped -- committed vector not present)")
        return
    }
    val json = f.readText(Charsets.UTF_8)

    // ---- RevocationRecord.bytes (§5.3) ---------------------------------------------------------
    // "record_bytes" appears under both "revocation" and "foreign_link"; scope to the revocation
    // block explicitly.
    run {
        val revBlockTop = objectField(json, "revocation") ?: throw IRFailure("revocation block missing")
        val cases = arrayField(revBlockTop, "record_bytes")
        if (cases.isEmpty()) throw IRFailure("revocation.record_bytes empty")
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("record_bytes case missing name")
            val r = Identity.RevocationRecord(
                key = strField(tc, "key") ?: throw IRFailure("$name: missing key"),
                notAfter = longField(tc, "not_after") ?: throw IRFailure("$name: missing not_after"),
            )
            val want = strField(tc, "bytes_hex") ?: throw IRFailure("$name: missing bytes_hex")
            eq("$name bytes", Hex.encode(r.bytes()), want)
            println("  ok  revocation.record_bytes $name")
        }
    }

    // ---- RevokedAt (§5.3) -- MUTATION ANCHOR "at_boundary_still_valid" pins `>` vs `>=`. ---------
    run {
        val revBlock = objectField(json, "revocation") ?: throw IRFailure("revocation block missing")
        val cases = arrayField(revBlock, "revoked_at")
        if (cases.isEmpty()) throw IRFailure("revocation.revoked_at empty")
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("revoked_at case missing name")
            val queryKey = strField(tc, "query_key") ?: throw IRFailure("$name: missing query_key")
            val queryPosition = longField(tc, "query_position") ?: throw IRFailure("$name: missing query_position")
            val expectRevoked = boolField(tc, "expect_revoked")
            val expectNotAfter = longField(tc, "expect_not_after")
            var revoked = false
            var notAfter = 0L
            for (rv in arrayField(tc, "revocations")) {
                val key = strField(rv, "key") ?: throw IRFailure("$name: revocation missing key")
                if (key != queryKey) continue
                val na = longField(rv, "not_after") ?: throw IRFailure("$name: revocation missing not_after")
                val rec = Identity.RevocationRecord(key, na)
                if (Identity.revokedAt(rec, queryPosition)) {
                    revoked = true
                    notAfter = na
                }
            }
            eq("$name revoked", revoked, expectRevoked)
            if (expectRevoked) eq("$name not_after", notAfter, expectNotAfter)
            println("  ok  revocation.revoked_at $name")
        }
    }

    // ---- VerifyRevocation (§5.3, §5.5) -----------------------------------------------------------
    // Membership BEFORE signature, fail-closed. MUTATION ANCHORS: "recovery_key_not_configured_reject"
    // (a valid recovery-key sig with an EMPTY authorized set -> SignerMismatch) and "wrong_key_reject".
    run {
        val revBlock = objectField(json, "revocation") ?: throw IRFailure("revocation block missing")
        val cases = arrayField(revBlock, "verify")
        if (cases.size < 7) throw IRFailure("revocation.verify: expected >=7 cases, got ${cases.size}")
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("verify case missing name")
            val recordObj = objectField(tc, "record") ?: throw IRFailure("$name: missing record")
            val rec = Identity.RevocationRecord(
                key = strField(recordObj, "key") ?: throw IRFailure("$name: record missing key"),
                notAfter = longField(recordObj, "not_after") ?: throw IRFailure("$name: record missing not_after"),
            )
            val alg = intField(tc, "candidate_alg") ?: throw IRFailure("$name: missing candidate_alg")
            eq("$name candidate_alg", alg, Cose.ALG_MLDSA65)
            val pub = Hex.decode(strField(tc, "candidate_pubkey_hex") ?: throw IRFailure("$name: missing candidate_pubkey_hex"))
            val sig = Hex.decode(strField(tc, "sig_hex") ?: throw IRFailure("$name: missing sig_hex"))
            val recoveryIds = stringArrayField(tc, "authorized_recovery_ids")
            val expectValid = boolField(tc, "expect_valid")
            val expectErrorKind = strField(tc, "expect_error_kind") ?: ""
            if (expectValid) {
                Identity.verifyRevocation(rec, alg, pub, sig, recoveryIds) // throws on unexpected failure
            } else {
                var kind = ""
                try {
                    Identity.verifyRevocation(rec, alg, pub, sig, recoveryIds)
                    throw IRFailure("$name: expected reject, got accept")
                } catch (e: NaalpException) {
                    kind = e.kind
                }
                if (expectErrorKind.isNotEmpty()) eq("$name error kind", kind, expectErrorKind)
            }
            println("  ok  revocation.verify $name")
        }
    }

    // ---- ForeignLinkRecord.bytes (§5.4) -- MUTATION ANCHOR: NFC/NFD must encode to different bytes.
    run {
        val flBlock = objectField(json, "foreign_link") ?: throw IRFailure("foreign_link block missing")
        val cases = arrayField(flBlock, "record_bytes")
        if (cases.size < 2) throw IRFailure("foreign_link.record_bytes: expected >=2 cases")
        val seen = HashMap<String, String>()
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("record_bytes case missing name")
            val r = Identity.ForeignLinkRecord(
                controls = strField(tc, "controls") ?: throw IRFailure("$name: missing controls"),
                foreignId = strField(tc, "foreign_id") ?: throw IRFailure("$name: missing foreign_id"),
                notAfter = longField(tc, "not_after") ?: throw IRFailure("$name: missing not_after"),
            )
            val want = strField(tc, "bytes_hex") ?: throw IRFailure("$name: missing bytes_hex")
            val got = Hex.encode(r.bytes())
            eq("$name bytes", got, want)
            seen[name] = got
            println("  ok  foreign_link.record_bytes $name")
        }
        val nfc = seen["nfc_form"]
        val nfd = seen["nfd_form_different_bytes"]
        if (nfc != null && nfd != null && nfc == nfd) {
            throw IRFailure("NFC and NFD foreign_id forms must encode to different bytes")
        }
    }

    // ---- VerifyForeignLink (§5.4, §5.5) ----------------------------------------------------------
    run {
        val flBlock = objectField(json, "foreign_link") ?: throw IRFailure("foreign_link block missing")
        val cases = arrayField(flBlock, "verify")
        if (cases.isEmpty()) throw IRFailure("foreign_link.verify empty")
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("verify case missing name")
            val recordObj = objectField(tc, "record") ?: throw IRFailure("$name: missing record")
            val rec = Identity.ForeignLinkRecord(
                controls = strField(recordObj, "controls") ?: throw IRFailure("$name: record missing controls"),
                foreignId = strField(recordObj, "foreign_id") ?: throw IRFailure("$name: record missing foreign_id"),
                notAfter = longField(recordObj, "not_after") ?: throw IRFailure("$name: record missing not_after"),
            )
            val alg = intField(tc, "candidate_alg") ?: throw IRFailure("$name: missing candidate_alg")
            eq("$name candidate_alg", alg, Cose.ALG_MLDSA65)
            val pub = Hex.decode(strField(tc, "candidate_pubkey_hex") ?: throw IRFailure("$name: missing candidate_pubkey_hex"))
            val sig = Hex.decode(strField(tc, "sig_hex") ?: throw IRFailure("$name: missing sig_hex"))
            val now = longField(tc, "now") ?: throw IRFailure("$name: missing now")
            val expectErrorKind = strField(tc, "expect_error_kind") ?: ""
            if (expectErrorKind.isNotEmpty()) {
                var kind = ""
                try {
                    Identity.verifyForeignLink(rec, alg, pub, sig, now)
                    throw IRFailure("$name: expected error $expectErrorKind, got no exception")
                } catch (e: NaalpException) {
                    kind = e.kind
                }
                eq("$name error kind", kind, expectErrorKind)
            } else {
                val linked = Identity.verifyForeignLink(rec, alg, pub, sig, now)
                val expectLinked = boolField(tc, "expect_linked")
                eq("$name linked", linked, expectLinked)
                if (expectLinked) {
                    eq("$name controls", rec.controls, strField(tc, "expect_controls"))
                    eq("$name foreign_id", rec.foreignId, strField(tc, "expect_foreign_id"))
                }
            }
            println("  ok  foreign_link.verify $name")
        }
    }

    // ---- RotationEvidence / Thread / ResolveThread (§5.2, R-1.4) ---------------------------------
    // "broken_link_old_mismatch" pins the CONTIGUITY guard; "broken_link_forged_old_signature" pins
    // the per-link CO-SIGNATURE guard (verifyRotation), isolating one guard from the other.
    run {
        val thBlock = objectField(json, "thread") ?: throw IRFailure("thread block missing")
        val cases = arrayField(thBlock, "resolve")
        if (cases.isEmpty()) throw IRFailure("thread.resolve empty")
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("resolve case missing name")
            val evs = arrayField(tc, "evidence").map { e ->
                val rec = Identity.RotationRecord(
                    oldId = strField(e, "old") ?: throw IRFailure("$name: evidence missing old"),
                    newId = strField(e, "new") ?: throw IRFailure("$name: evidence missing new"),
                    notBefore = longField(e, "not_before") ?: throw IRFailure("$name: evidence missing not_before"),
                )
                val wantBytes = strField(e, "record_bytes_hex") ?: throw IRFailure("$name: evidence missing record_bytes_hex")
                eq("$name RotationRecord.bytes (evidence input)", Hex.encode(rec.bytes()), wantBytes)
                Identity.RotationEvidence(
                    record = rec,
                    oldAlg = intField(e, "old_alg") ?: throw IRFailure("$name: evidence missing old_alg"),
                    oldPub = Hex.decode(strField(e, "old_pubkey_hex") ?: throw IRFailure("$name: evidence missing old_pubkey_hex")),
                    newAlg = intField(e, "new_alg") ?: throw IRFailure("$name: evidence missing new_alg"),
                    newPub = Hex.decode(strField(e, "new_pubkey_hex") ?: throw IRFailure("$name: evidence missing new_pubkey_hex")),
                    oldSig = Hex.decode(strField(e, "old_sig_hex") ?: throw IRFailure("$name: evidence missing old_sig_hex")),
                    newSig = Hex.decode(strField(e, "new_sig_hex") ?: throw IRFailure("$name: evidence missing new_sig_hex")),
                )
            }
            val expectError = strField(tc, "expect_error") ?: ""
            if (expectError.isNotEmpty()) {
                var kind = ""
                try {
                    Identity.resolveThread(evs)
                    throw IRFailure("$name: expected error $expectError, got accept")
                } catch (e: NaalpException) {
                    kind = e.kind
                }
                eq("$name error kind", kind, expectError)
            } else {
                val th = Identity.resolveThread(evs)
                val want = objectField(tc, "expect_thread") ?: throw IRFailure("$name: missing expect_thread")
                eq("$name root", th.root, strField(want, "root"))
                eq("$name current", th.current, strField(want, "current"))
                eq("$name chain", th.chain, stringArrayField(want, "chain"))
            }
            println("  ok  thread.resolve $name")
        }
    }

    // ---- Thread.attributable -- "unrelated_key_not_attributable" is the MUTATION ANCHOR. ---------
    run {
        val thBlock = objectField(json, "thread") ?: throw IRFailure("thread block missing")
        val cases = arrayField(thBlock, "attributable")
        if (cases.isEmpty()) throw IRFailure("thread.attributable empty")
        for (tc in cases) {
            val name = strField(tc, "name") ?: throw IRFailure("attributable case missing name")
            val thJson = objectField(tc, "thread") ?: throw IRFailure("$name: missing thread")
            val th = Identity.Thread(
                root = strField(thJson, "root") ?: throw IRFailure("$name: thread missing root"),
                current = strField(thJson, "current") ?: throw IRFailure("$name: thread missing current"),
                chain = stringArrayField(thJson, "chain"),
            )
            val query = strField(tc, "query") ?: throw IRFailure("$name: missing query")
            val expect = boolField(tc, "expect")
            eq("$name attributable", th.attributable(query), expect)
            println("  ok  thread.attributable $name")
        }
    }

    println("IdentityRecordsKatTest: PASS")
}
