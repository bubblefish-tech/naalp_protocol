// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * CBOR decoder nesting-depth bound (design.md §3.4, R7) known-answer test for the Kotlin SDK,
 * mirroring impl/go/cbor/bounds_test.go and impl/rust/src/cbor.rs's bound test: the outermost item
 * is depth 1, and decodeBounded rejects the first item at depth maxDepth+1 with a DepthExceeded
 * error, before it is materialized. The unbounded decode path still accepts the same structure, so
 * the bound -- not another check -- is what does the work.
 *
 * Run (main()-driven, no test framework):
 *   kotlinc src/main/kotlin src/test/kotlin/CborBoundsTests.kt -include-runtime -d out/cbor-bounds.jar
 *   java -cp out/cbor-bounds.jar sh.bubblefish.naalp.CborBoundsTestsKt
 */

private class CborBoundsFailure(msg: String) : RuntimeException(msg)

private fun cbOk(what: String) = println("  ok  $what")

/** k single-element arrays (0x81) wrapping a zero scalar (0x00): decoding it, the outermost array
 *  is at depth 1 and the innermost scalar is at depth k+1. */
private fun nestedArraysCbor(k: Int): ByteArray {
    val out = ByteArray(k + 1)
    for (i in 0 until k) out[i] = 0x81.toByte()
    out[k] = 0x00
    return out
}

/** Run [block]; return "ok" if it returns, else the NaalpException kind. */
private fun cbVerifyKind(block: () -> Unit): String = try {
    block()
    "ok"
} catch (e: NaalpException) {
    e.kind
}

// TestDecodeBoundedDepth pins the nesting-depth counter (design.md §3.4, R7): the outermost item is
// depth 1, and decodeBounded rejects the first item at depth maxDepth+1 with a DepthExceeded error,
// before it is materialized. The unbounded decode path still accepts the same structure, so the
// bound is what does the work.
private fun testDecodeBoundedDepth() {
    val d = 3

    // deepest scalar at depth d (k = d-1): accepted at maxDepth=d.
    val atLimit = nestedArraysCbor(d - 1)
    val atLimitKind = cbVerifyKind { Cbor.decodeBounded(atLimit, d) }
    if (atLimitKind != "ok") {
        throw CborBoundsFailure("deepest item at depth $d should decode at maxDepth=$d, got $atLimitKind")
    }
    cbOk("deepest item at depth $d decodes at maxDepth=$d")

    // deepest scalar at depth d+1 (k = d): rejected DepthExceeded at maxDepth=d.
    val over = nestedArraysCbor(d)
    val overKind = cbVerifyKind { Cbor.decodeBounded(over, d) }
    if (overKind != "DepthExceeded") {
        throw CborBoundsFailure("deepest item at depth ${d + 1} should be DepthExceeded at maxDepth=$d, got $overKind")
    }
    cbOk("deepest item at depth ${d + 1} rejected DepthExceeded at maxDepth=$d")

    // The unbounded path accepts the same over-depth structure: the bound, not another check, is
    // what rejected it above.
    val unboundedKind = cbVerifyKind { Cbor.decode(over) }
    if (unboundedKind != "ok") {
        throw CborBoundsFailure("unbounded decode should accept the depth-${d + 1} structure, got $unboundedKind")
    }
    cbOk("unbounded decode accepts the depth-${d + 1} structure")
}

fun main() {
    println("CborBoundsTests -- CBOR decoder nesting-depth bound (design.md §3.4, R7)")
    testDecodeBoundedDepth()
    println("CborBoundsTests: PASS")
}
