// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

//
// C5 §6 authorization conformance for the Kotlin SDK, graded against the shared independent corpus
// vectors/effect/cases.json (NOT produced by this code): the granted×effect authorization matrix
// (R-6.3), the signature-only authorization-principal rule (R-6.5), and the strict optional
// safety-label extraction (R-6.4). Fail-closed throughout.
//
// KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
// "Tests" token the ten-language-parity gate indexes. The recorded mutation forces
// Policy.Grant.authorizeObject to skip the ceiling check, which flips the denied authorization-matrix
// rows on their EffectNotAuthorized assertion.
//

private var polFails = 0

private fun polCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        polFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

private fun polErrKind(fn: () -> Unit): String =
    try {
        fn()
        "no-error"
    } catch (e: NaalpException) {
        e.kind
    } catch (t: Throwable) {
        t.javaClass.simpleName
    }

// ---- nesting-aware JSON access (Kotlin has no JSON library) ----

private fun polFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/effect/cases.json not found")
        val p = File(File(cur, "vectors"), "effect/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/effect/cases.json not found from ${File(".").absolutePath}")
}

private fun polMatchClose(s: String, open: Int): Int {
    val oc = s[open]
    val cc = if (oc == '{') '}' else ']'
    var depth = 0
    var inStr = false
    var i = open
    while (i < s.length) {
        val ch = s[i]
        if (inStr) {
            when (ch) {
                '\\' -> i++
                '"' -> inStr = false
            }
        } else {
            when (ch) {
                '"' -> inStr = true
                oc -> depth++
                cc -> { depth--; if (depth == 0) return i + 1 }
            }
        }
        i++
    }
    throw AssertionError("unbalanced from $open")
}

private fun polAfterKey(s: String, key: String): Int {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:").find(s)
        ?: throw AssertionError("key not found: $key")
    return m.range.last + 1
}

// The array block for a key ("key": [ ... ]).
private fun polArrayBlock(s: String, key: String): String {
    val open = s.indexOf('[', polAfterKey(s, key))
    val close = polMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

// The object block for a key whose value is an object ("key": { ... }); anchors on the '{' after the
// colon so a same-named string field elsewhere (bridge_mapping's "safety_label": "...") is skipped.
private fun polObjBlockStrict(s: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\\{").find(s)
        ?: throw AssertionError("object key not found: $key")
    val open = m.range.last // the '{'
    val close = polMatchClose(s, open)
    return s.substring(open + 1, close - 1)
}

private fun polSplitObjects(arrayInner: String): List<String> {
    val out = ArrayList<String>()
    var i = 0
    while (true) {
        val open = arrayInner.indexOf('{', i)
        if (open < 0) return out
        val close = polMatchClose(arrayInner, open)
        out.add(arrayInner.substring(open + 1, close - 1))
        i = close
    }
}

private fun polField(scope: String, key: String): String {
    val m = Regex("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun polIntField(scope: String, key: String): Long {
    val m = Regex("\"" + key + "\"\\s*:\\s*(-?\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun polBoolField(scope: String, key: String): Boolean {
    val m = Regex("\"" + key + "\"\\s*:\\s*(true|false)").find(scope)
        ?: throw AssertionError("bool key not found: $key")
    return m.groupValues[1] == "true"
}

private fun polSrcOf(s: String): Policy.PrincipalSource = when (s) {
    "signature" -> Policy.PrincipalSource.SIGNATURE
    "transport_metadata" -> Policy.PrincipalSource.TRANSPORT_METADATA
    "foreign_header" -> Policy.PrincipalSource.FOREIGN_HEADER
    "client_name" -> Policy.PrincipalSource.CLIENT_NAME
    else -> throw AssertionError("unknown source $s")
}

fun main() {
    val json = polFindVector().readText()

    // 1. R-6.3 — the granted×effect authorization matrix.
    val matrix = polSplitObjects(polArrayBlock(json, "authorization_matrix"))
    polCheck("matrix has 16 cells", matrix.size.toString(), "16")
    var allows = 0
    var denies = 0
    for (r in matrix) {
        val granted = polIntField(r, "granted")
        val effect = polIntField(r, "effect")
        val allow = polBoolField(r, "allow")
        val g = Policy.Grant("pA", granted)
        if (allow) {
            allows++
            polCheck("granted=$granted effect=$effect allowed",
                polErrKind { g.authorizeObject(Policy.PrincipalSource.SIGNATURE, "pA", effect) }, "no-error")
        } else {
            denies++
            polCheck("granted=$granted effect=$effect denied (EffectNotAuthorized)",
                polErrKind { g.authorizeObject(Policy.PrincipalSource.SIGNATURE, "pA", effect) }, "EffectNotAuthorized")
        }
        polCheck("lattice authorizes(granted=$granted, norm(effect=$effect))",
            if (Policy.authorizes(granted, Policy.normalizeEffect(effect))) "yes" else "no",
            if (allow) "yes" else "no")
    }
    polCheck("matrix exercises both allow and deny", if (allows > 0 && denies > 0) "yes" else "no", "yes")

    // 2. R-6.5 — only a signature-derived identity is an authorization principal.
    val g = Policy.Grant("pA", Policy.DESTRUCTIVE) // maximally permissive
    for (ps in polSplitObjects(polArrayBlock(json, "principal_sources"))) {
        val srcName = polField(ps, "source")
        val src = polSrcOf(srcName)
        val accepted = polBoolField(ps, "accepted")
        if (accepted) {
            polCheck("source $srcName accepted", polErrKind { Policy.resolveAuthPrincipal(src, "pA") }, "no-error")
            polCheck("source $srcName authorizes read_only",
                polErrKind { g.authorizeObject(src, "pA", Policy.READ_ONLY) }, "no-error")
        } else {
            polCheck("source $srcName refused (UnauthenticatedPrincipal)",
                polErrKind { Policy.resolveAuthPrincipal(src, "pA") }, "UnauthenticatedPrincipal")
            polCheck("source $srcName denies read_only (UnauthenticatedPrincipal)",
                polErrKind { g.authorizeObject(src, "pA", Policy.READ_ONLY) }, "UnauthenticatedPrincipal")
        }
    }

    // 3. R-6.4 — safetyLabelFromExt strict extraction (matching the independently-hex-pinned oracle).
    val sl = polObjBlockStrict(json, "safety_label")
    val risk = polField(sl, "risk")
    val scope = polField(sl, "scope")
    val extKey = polIntField(sl, "ext_key")
    val cborHex = polField(sl, "cbor_hex")

    val ext = Cbor.M(listOf(Cbor.Pair(Cbor.U(extKey),
        Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.T(risk)), Cbor.Pair(Cbor.U(2), Cbor.T(scope)))))))
    val (label, present) = Policy.safetyLabelFromExt(ext)
    polCheck("safety label present", if (present) "yes" else "no", "yes")
    polCheck("safety label risk == oracle", label?.risk ?: "<null>", risk)
    polCheck("safety label scope == oracle", label?.scope ?: "<null>", scope)
    polCheck("safety label body == oracle hex", Hex.encode(Policy.safetyLabelBytes(risk, scope)), cborHex)

    val (absentLabel, absentPresent) = Policy.safetyLabelFromExt(Cbor.M(emptyList()))
    polCheck("absent ext -> not present", if (absentLabel == null && !absentPresent) "yes" else "no", "yes")

    val badNonMap = Cbor.M(listOf(Cbor.Pair(Cbor.U(extKey), Cbor.U(9))))
    polCheck("malformed (non-map) rejected (MalformedSafetyLabel)",
        polErrKind { Policy.safetyLabelFromExt(badNonMap) }, "MalformedSafetyLabel")

    val badIncomplete = Cbor.M(listOf(Cbor.Pair(Cbor.U(extKey),
        Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.T("x")))))))
    polCheck("incomplete (missing scope) rejected (MalformedSafetyLabel)",
        polErrKind { Policy.safetyLabelFromExt(badIncomplete) }, "MalformedSafetyLabel")

    println(if (polFails == 0) "PASS" else "FAIL ($polFails)")
    if (polFails != 0) exitProcess(1)
}
