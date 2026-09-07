// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import kotlin.system.exitProcess

/**
 * T3.3 naalp-error object + numeric error-code registry known-answer tests for the Kotlin SDK,
 * mirroring impl/go/naalperror/naalperror.go and impl/rust/src/naalperror.rs (design.md §3.5,
 * R3.3/R3.4) and the parallel port tests (impl/python/tests/test_naalperror.py,
 * impl/typescript/test/naalperror.test.mjs, impl/ruby/test/test_naalperror.rb,
 * impl/php/test/naalperror_test.php, impl/csharp/NaalpError.cs). The encode KATs are hand-computed
 * canonical CBOR, independent of the oracle and of impl/go — Kotlin MUST reproduce the same bytes as
 * every other port.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
 * "Tests" token the ten-language-parity gate indexes.
 *
 * Mutation anchors: [testDualCarriageMismatchIsMalformed] (drops the registered-code/name-agreement
 * check) and [testUnknownCodeIsOpaque] (rejects unknown codes instead of treating them as opaque) are
 * each a single specific behaviour with no other test covering it.
 */

private var errFails = 0

private fun errCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        errFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

private inline fun errKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

// 1. registry size + index: exactly 129 unique names, code == index+1 in both directions.
private fun testRegistrySizeAndIndex() {
    errCheck("registry size", NaalpError.NAMES.size.toString(), "132")
    val seen = HashSet<String>()
    for ((i, n) in NaalpError.NAMES.withIndex()) {
        if (!seen.add(n)) throw AssertionError("duplicate name $n at code ${i + 1}")
        errCheck("codeForName($n)", NaalpError.codeForName(n).toString(), (i + 1).toString())
        val (name, registered) = NaalpError.nameForCode((i + 1).toLong())
        errCheck("nameForCode(${i + 1}) registered", registered.toString(), "true")
        errCheck("nameForCode(${i + 1}) name", name, n)
    }
}

// 2. MANDATORY KATs: hand-computed canonical CBOR of {1:code, 2:name}, independent of the oracle
//    and impl/go.
private fun testEncodeKat() {
    errCheck(
        "encode(1,NonCanonical)",
        Hex.encode(NaalpError.encode(1, "NonCanonical", "", null)),
        "a20101026c4e6f6e43616e6f6e6963616c",
    )
    errCheck(
        "encode(52,NotDelivered)",
        Hex.encode(NaalpError.encode(52, "NotDelivered", "", null)),
        "a2011834026c4e6f7444656c697665726564",
    )
}

// 3. full grammar round-trip: optional fields 3 (detail) and 4 (subject) present together.
private fun testEncodeDecodeFull() {
    val subj = ByteArray(50)
    val code = NaalpError.codeForName("BadSignature") ?: throw AssertionError("BadSignature not registered")
    val b = NaalpError.encode(code, "BadSignature", "reason", subj)
    val o = NaalpError.decode(b)
    errCheck("round-trip name", o.name, "BadSignature")
    errCheck("round-trip detail", o.detail, "reason")
    errCheck("round-trip subject length", (o.subject?.size ?: -1).toString(), "50")
}

// 4. MANDATORY KAT [MUTATION ANCHOR]: a registered code (22=BadSignature) carrying the wrong
//    registered name (NotDelivered, code 52) is rejected Malformed — the strengthening direction.
private fun testDualCarriageMismatchIsMalformed() {
    val code = NaalpError.codeForName("BadSignature") ?: throw AssertionError("BadSignature not registered")
    val b = NaalpError.encode(code, "NotDelivered", "", null)
    errCheck("dual-carriage mismatch rejected", errKind { NaalpError.decode(b) }, "Malformed")
}

// 5. MANDATORY KAT [MUTATION ANCHOR]: a code outside the registry is accepted opaque (open-registry
//    contract) — decode(encode(60000, "SomeFutureError")) must be ACCEPTED, not rejected.
private fun testUnknownCodeIsOpaque() {
    val b = NaalpError.encode(60000, "SomeFutureError", "", null)
    val o = NaalpError.decode(b)
    errCheck("unknown code round-trips code", o.code.toString(), "60000")
    errCheck("unknown code round-trips name", o.name, "SomeFutureError")
}

// 6. nameForCode/codeForName boundaries: 0, past the registered range, and a large unregistered
//    standards-range code are all unregistered.
private fun testNameForCodeBoundaries() {
    for (code in longArrayOf(1L, 22L, 119L)) {
        val (_, registered) = NaalpError.nameForCode(code)
        errCheck("nameForCode($code) registered", registered.toString(), "true")
    }
    for (code in longArrayOf(0L, 133L, 60000L)) {
        val (_, registered) = NaalpError.nameForCode(code)
        errCheck("nameForCode($code) unregistered", registered.toString(), "false")
    }
    errCheck("STANDARDS_MAX", NaalpError.STANDARDS_MAX.toString(), "32767")
}

// 7. the dual-carriage MALFORMED half: a structurally malformed body (not a map, a non-integer key,
//    a wrong-typed or unknown field, or a missing code/name) is rejected Malformed.
private fun testMalformedStructuralRejections() {
    errCheck(
        "not a map rejected",
        errKind { NaalpError.decode(Cbor.encode(Cbor.U(1))) },
        "Malformed",
    )
    val unknownFieldBody = Cbor.encode(
        Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.U(1)),
                Cbor.Pair(Cbor.U(2), Cbor.T("NonCanonical")),
                Cbor.Pair(Cbor.U(5), Cbor.U(9)),
            )
        )
    )
    errCheck("unknown field key rejected", errKind { NaalpError.decode(unknownFieldBody) }, "Malformed")

    val missingNameBody = Cbor.encode(Cbor.M(listOf(Cbor.Pair(Cbor.U(1), Cbor.U(1)))))
    errCheck("missing name rejected", errKind { NaalpError.decode(missingNameBody) }, "Malformed")

    val wrongTypedCodeBody = Cbor.encode(
        Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.T("not-a-uint")),
                Cbor.Pair(Cbor.U(2), Cbor.T("NonCanonical")),
            )
        )
    )
    errCheck("wrong-typed code rejected", errKind { NaalpError.decode(wrongTypedCodeBody) }, "Malformed")
}

fun main() {
    println("naalp-error conformance (Kotlin) — T3.3, mirrors impl/go/naalperror + impl/rust/src/naalperror.rs")
    testRegistrySizeAndIndex()
    testEncodeKat()
    testEncodeDecodeFull()
    testDualCarriageMismatchIsMalformed()
    testUnknownCodeIsOpaque()
    testNameForCodeBoundaries()
    testMalformedStructuralRejections()
    println(if (errFails == 0) "NaalpErrorTests: PASS" else "NaalpErrorTests: FAIL ($errFails)")
    exitProcess(if (errFails == 0) 0 else 1)
}
