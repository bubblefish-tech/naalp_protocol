// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import kotlin.system.exitProcess

/**
 * T20.1 Reconcile state machine verify-event known-answer tests for the Kotlin SDK — the choke
 * point [Federation.verifyReconcileOrder] (ietf draft "## Reconcile state machine", error code 61),
 * mirroring impl/go/federation/verify_reconcile_test.go. Self-contained (no vectors JSON oracle —
 * the causal graph is small enough to construct inline, and the content ids are picked so their
 * bytewise order is unambiguous).
 *
 * Two causally-INDEPENDENT objects idA=[0x01] and idB=[0x02]: [Federation.reconcile] ties
 * concurrent objects by content id (bytewise ascending), so the ONE deterministic order is
 * [idA, idB]. Four subtests: the claimed order agrees (verified — no throw); the claimed order is
 * a causally-valid-but-non-deterministic permutation (ReconcileMismatch); the claimed order drops
 * an element (ReconcileMismatch, the length-mismatch branch); and a cyclic node set is rejected
 * under the graph fault (CausalViolation) before any order comparison, fail-closed.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
 * "Tests" token the ten-language-parity gate indexes. [MUTATION ANCHOR]: neutering the order
 * comparison in verifyReconcileOrder (returning normally right after the reconcile() call, before
 * the length/element compare) flips "mismatch rejected" and "mismatch-length rejected" RED.
 */

private var rcoFails = 0

private fun rcoCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        rcoFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

/** The named kind thrown by [block], or "no-error". */
private inline fun rcoKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private val idA = byteArrayOf(0x01)
private val idB = byteArrayOf(0x02)
private val concurrentNodes = listOf(
    Federation.CausalNode(idA, emptyList()),
    Federation.CausalNode(idB, emptyList()),
)

// 1. agrees: the claimed order IS the deterministic order -> verified (returns normally).
private fun testAgrees() {
    val rec = Federation.ReconcileRecord(listOf("auth-1"), listOf(idA, idB))
    rcoCheck("agreeing record verified", rcoKind { Federation.verifyReconcileOrder(rec, concurrentNodes) }, "no-error")
}

// 2. MUTATION ANCHOR: a causally-VALID-but-different order (the two objects are concurrent, so
//    [idB, idA] is causally valid) is not the deterministic order -> ReconcileMismatch.
private fun testMismatch() {
    val rec = Federation.ReconcileRecord(listOf("auth-1"), listOf(idB, idA))
    rcoCheck("mismatch rejected", rcoKind { Federation.verifyReconcileOrder(rec, concurrentNodes) }, "ReconcileMismatch")
}

// 3. MUTATION ANCHOR: a wrong-length claim (a dropped element) -> ReconcileMismatch.
private fun testMismatchLength() {
    val rec = Federation.ReconcileRecord(listOf("auth-1"), listOf(idA))
    rcoCheck("mismatch-length rejected", rcoKind { Federation.verifyReconcileOrder(rec, concurrentNodes) }, "ReconcileMismatch")
}

// 4. causal-violation: a cyclic node set is not a valid partial order; the recomputation rejects
//    it before any order comparison, so the record is rejected under the graph fault, fail-closed.
private fun testCausalViolation() {
    val idC = byteArrayOf(0x03)
    val idD = byteArrayOf(0x04)
    val cyclic = listOf(
        Federation.CausalNode(idC, listOf(idD)),
        Federation.CausalNode(idD, listOf(idC)),
    )
    val rec = Federation.ReconcileRecord(listOf("auth-1"), listOf(idC, idD))
    rcoCheck("causal-violation rejected", rcoKind { Federation.verifyReconcileOrder(rec, cyclic) }, "CausalViolation")
}

fun main() {
    println("reconcile-order conformance (Kotlin) — Federation.verifyReconcileOrder, mirrors impl/go/federation/verify_reconcile_test.go")
    testAgrees()
    testMismatch()
    testMismatchLength()
    testCausalViolation()
    println(if (rcoFails == 0) "ReconcileOrderTests: PASS" else "ReconcileOrderTests: FAIL ($rcoFails)")
    exitProcess(if (rcoFails == 0) 0 else 1)
}
