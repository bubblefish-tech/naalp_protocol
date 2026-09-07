// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File
import kotlin.system.exitProcess

/**
 * C8 delivery known-answer test for the Kotlin SDK (design.md §9; R-9.1..9.4), graded against the
 * shared independent corpus vectors/delivery/cases.json (NOT produced by this code).
 *
 * CORPUS-GRADED (pure): the four monotonic stage names + constants, and the byte-exact signed
 * delivery.update body for each stage. ISOLATION (real behaviour the corpus carries no vector for,
 * stated honestly, NOT corpus-graded): the delivery.update signature is real deterministic ML-DSA-65
 * (Kotlin is a full-signature port); the persist-before-acknowledge WAL tracker enforces monotonic
 * stages, StageOutOfOrder on regression, an idempotent re-report, and durable replay after reopen;
 * the switchboard passes objects through both directions concurrently; and the content-free relay
 * retains only a C7 audit chain over content ids that verifies offline.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
 * "Tests" token the ten-language-parity gate indexes. Written test-first: [Delivery] is absent until
 * Delivery.kt lands, so this fails RED with a kotlinc "unresolved reference: Delivery". A mutation
 * forcing the encoded stage field to a constant flips "delivery update body stage=1 == oracle".
 */

private var dvFails = 0

private fun dvCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        dvFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

// ---- balanced-brace / regex JSON access (no JSON library on the Kotlin port) ----

private fun dvFindVector(): File {
    var d: File? = File(".").absoluteFile
    repeat(6) {
        val cur = d ?: throw AssertionError("vectors/delivery/cases.json not found")
        val p = File(File(cur, "vectors"), "delivery/cases.json")
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw AssertionError("vectors/delivery/cases.json not found from ${File(".").absolutePath}")
}

private fun dvSection(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*").find(scope)
        ?: throw AssertionError("key not found: $key")
    var i = m.range.last + 1
    while (i < scope.length && scope[i].isWhitespace()) i++
    val open = scope[i]
    val close = when (open) { '{' -> '}'; '[' -> ']'; else -> throw AssertionError("not object/array at $key") }
    var depth = 0; var inStr = false; var esc = false; val start = i
    while (i < scope.length) {
        val c = scope[i]
        if (inStr) {
            when { esc -> esc = false; c == '\\' -> esc = true; c == '"' -> inStr = false }
        } else {
            when (c) { '"' -> inStr = true; open -> depth++; close -> { depth--; if (depth == 0) return scope.substring(start, i + 1) } }
        }
        i++
    }
    throw AssertionError("unbalanced value at key: $key")
}

private fun dvElements(arraySection: String): List<String> {
    val out = ArrayList<String>(); var i = 1; var inStr = false; var esc = false; var depth = 0; var start = -1
    while (i < arraySection.length - 1) {
        val c = arraySection[i]
        if (inStr) {
            when { esc -> esc = false; c == '\\' -> esc = true; c == '"' -> inStr = false }
        } else {
            when (c) {
                '"' -> inStr = true
                '{' -> { if (depth == 0) start = i; depth++ }
                '}' -> { depth--; if (depth == 0 && start >= 0) { out.add(arraySection.substring(start, i + 1)); start = -1 } }
            }
        }
        i++
    }
    return out
}

private fun dvStr(scope: String, key: String): String {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*\"([^\"]*)\"").find(scope)
        ?: throw AssertionError("string key not found: $key")
    return m.groupValues[1]
}

private fun dvInt(scope: String, key: String): Long {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(\\d+)").find(scope)
        ?: throw AssertionError("int key not found: $key")
    return m.groupValues[1].toLong()
}

private fun dvHex(s: String): ByteArray = Hex.decode(s)

private const val DV_ALG = Cose.ALG_MLDSA65
private val DV_SEED = ByteArray(32)
private val DV_PK = Cose.mldsaKeygen("ML-DSA-65", ByteArray(32))

private inline fun dvKind(block: () -> Unit): String = try {
    block(); "no-error"
} catch (e: NaalpException) {
    e.kind
}

private fun deliveryRun() {
    val json = dvFindVector().readText(Charsets.UTF_8)

    // 1. the four monotonic stage names + constants align with the corpus vocabulary.
    val stages = dvElements(dvSection(json, "stages"))
    val values = ArrayList<Long>()
    for (sb in stages) {
        val value = dvInt(sb, "value")
        val name = dvStr(sb, "name")
        dvCheck("stage name value=$value == oracle", Delivery.stageName(value), name)
        values.add(value)
    }
    dvCheck("stageName(99) unknown", Delivery.stageName(99), "unknown")
    dvCheck(
        "stage constants align with corpus, monotonic",
        listOf(Delivery.STAGE_PERSISTED_ORIGIN, Delivery.STAGE_ACCEPTED_RELAY, Delivery.STAGE_PERSISTED_TARGET, Delivery.STAGE_PRESENTED).joinToString(","),
        values.joinToString(","),
    )

    // 2. each of the four stages encodes a distinct signed delivery.update body == the oracle.
    val obj = dvHex(dvStr(json, "obj_content_id_hex"))
    for (uv in dvElements(dvSection(json, "updates"))) {
        val stage = dvInt(uv, "stage")
        val u = Delivery.DeliveryUpdate(obj, stage, dvInt(uv, "at"))
        dvCheck("delivery update body stage=$stage == oracle", Hex.encode(u.bytes()), dvStr(uv, "body_hex"))
    }

    // 3. the delivery.update signature is a real deterministic ML-DSA-65 round-trip (ISOLATION).
    run {
        val u = Delivery.DeliveryUpdate(obj, Delivery.STAGE_PRESENTED, 103)
        val sig = Delivery.signUpdate(u, DV_ALG, DV_SEED)
        dvCheck("signed update verifies", Delivery.verifyUpdate(u, DV_ALG, DV_PK, sig).toString(), "true")
        val bad = sig.copyOf(); bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 1).toByte()
        dvCheck("tampered update rejected", Delivery.verifyUpdate(u, DV_ALG, DV_PK, bad).toString(), "false")
    }

    // 4. WAL tracker: monotonic persist-before-ack, StageOutOfOrder on regression, idempotent
    //    re-report, and durable recovery after reopen (ISOLATION, tempfile WAL).
    run {
        val tmp = File.createTempFile("naalp-delivery-", ".wal")
        try {
            val t = Delivery.openTracker(tmp.absolutePath)
            t.advance(obj, Delivery.STAGE_PERSISTED_ORIGIN, 100)
            t.advance(obj, Delivery.STAGE_PERSISTED_TARGET, 102) // skipping ahead is permitted
            dvCheck("regression rejected", dvKind { t.advance(obj, Delivery.STAGE_ACCEPTED_RELAY, 103) }, "StageOutOfOrder")
            val same = t.advance(obj, Delivery.STAGE_PERSISTED_TARGET, 104) // idempotent re-report
            dvCheck("idempotent re-report stage", same.stage.toString(), Delivery.STAGE_PERSISTED_TARGET.toString())
            val (s1, seen1) = t.stage(obj)
            dvCheck("tracked stage before reopen", "$s1/$seen1", "${Delivery.STAGE_PERSISTED_TARGET}/true")
            t.close()
            val t2 = Delivery.openTracker(tmp.absolutePath)
            val (s2, seen2) = t2.stage(obj)
            dvCheck("durable stage after reopen (replay)", "$s2/$seen2", "${Delivery.STAGE_PERSISTED_TARGET}/true")
            val (s3, seen3) = t2.stage("unseen".toByteArray(Charsets.UTF_8))
            dvCheck("unseen object not tracked", "$s3/$seen3", "0/false")
            t2.close()
        } finally {
            tmp.delete()
        }
    }

    // 5. the switchboard passes objects through both directions concurrently (ISOLATION).
    run {
        val sb = Delivery.Switchboard(4)
        try {
            sb.left().send("L->R".toByteArray(Charsets.UTF_8))
            sb.right().send("R->L".toByteArray(Charsets.UTF_8))
            dvCheck("switchboard L->R delivered", String(sb.right().recv(), Charsets.UTF_8), "L->R")
            dvCheck("switchboard R->L delivered", String(sb.left().recv(), Charsets.UTF_8), "R->L")
        } finally {
            sb.close()
        }
    }

    // 6. the content-free relay retains only a C7 receipt chain over content ids that verifies
    //    offline; the receipt names the object's content id, not the payload (ISOLATION).
    run {
        val relay = Delivery.ContentFreeRelay(DV_ALG, DV_SEED)
        val one = relay.route("object-one".toByteArray(Charsets.UTF_8), 100)
        val two = relay.route("object-two".toByteArray(Charsets.UTF_8), 101)
        dvCheck("relay returns object-one for forwarding", String(one, Charsets.UTF_8), "object-one")
        dvCheck("relay returns object-two for forwarding", String(two, Charsets.UTF_8), "object-two")
        val (receipts, sigs) = relay.auditTrail()
        dvCheck("relay retained two receipts", receipts.size.toString(), "2")
        val cid = Delivery.contentId("object-one".toByteArray(Charsets.UTF_8))
        dvCheck("receipt names content id, not payload", Hex.encode(receipts[0].obj), Hex.encode(cid))
        dvCheck("content id carries T1 framing prefix", Hex.encode(cid.copyOfRange(0, 2)), "2030")
        dvCheck("retained relay trail verifies as a chain", dvKind { Audit.verifyChain(receipts, sigs, DV_ALG, DV_PK) }, "no-error")
    }
}

fun main() {
    println("delivery conformance (Kotlin) — graded vs vectors/delivery/cases.json")
    deliveryRun()
    println(if (dvFails == 0) "DeliveryTests: PASS" else "DeliveryTests: FAIL ($dvFails)")
    exitProcess(if (dvFails == 0) 0 else 1)
}
