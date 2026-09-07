// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.File

/**
 * C10 channel-state-machine + Workflow-input-gate cluster (design-channels.md §1..§20, §18)
 * known-answer + fail-closed tests for the Kotlin SDK.
 *
 * CORPUS-GRADED (pure, non-circular per F3): every one of the twenty channels' (channel_id, name,
 * kinds[code/name/effect/variable], states, transitions[from/to], errors) against the independent
 * per-channel oracle under vectors/channels/<lowercase-name>/cases.json — the SAME oracle Go and
 * Rust grade against (Kotlin == Go == Rust == oracle on the whole channel table).
 *
 * ISOLATION (self-contained, no vector — behavioural, mirrors Go channels_test.go /
 * impl/rust/src/channels.rs #[cfg(test)]): AllowedTransition representative accept/reject cases;
 * CheckFrameTree accept-valid-tree / reject-cyclic; and the Workflow durable input/approval gate
 * crash test (design-channels.md §18) that proves InputGateBypass cannot occur even across a
 * simulated crash (close -> reopen with no input yet supplied).
 *
 * The load-bearing MUTATION ANCHOR: WorkflowGate.run's `"awaiting-input", "awaiting-approval" ->
 * throw InputGateBypass` branch is the fail-closed check that a task may not execute on input that
 * was never supplied/authorized. Neutering it (letting an ungated task fall through to "running")
 * flips the "task cannot run before its input gate" / "task cannot run after a crash without
 * passing the gate" assertions in workflowGateInputBypassRun() below from PASS to FAIL.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure (mirrors ApprovalKatTest.kt /
 * RotationKatTest.kt / ProducingBoundaryKatTest.kt); the filename carries the "KatTest" token the
 * ten-language-parity gate indexes.
 */

// ---- balanced-brace / regex JSON access (string-aware; mirrors ApprovalKatTest.kt) ----------------

private class ChanFailure(msg: String) : RuntimeException(msg)

private var katFails = 0

private fun katOk(name: String) = println("  ok   $name")

private fun katFail(name: String, detail: String) {
    katFails++
    println("  FAIL $name\n       $detail")
}

private fun katCheck(name: String, got: String, want: String) {
    if (got == want) katOk(name) else katFail(name, "got  $got\n       want $want")
}

private fun katCheckBool(name: String, got: Boolean, want: Boolean) {
    if (got == want) katOk(name) else katFail(name, "got $got want $want")
}

/** Run [block]; require it throws a [NaalpException] whose kind == [wantKind]. */
private fun katExpectThrows(name: String, wantKind: String, block: () -> Unit) {
    try {
        block()
        katFail(name, "expected $wantKind, no exception thrown")
    } catch (e: NaalpException) {
        katCheck(name, e.kind, wantKind)
    }
}

/** Run [block]; require it does NOT throw. */
private fun katExpectOk(name: String, block: () -> Unit) {
    try {
        block()
        katOk(name)
    } catch (e: NaalpException) {
        katFail(name, "expected no error, got ${e.kind}: ${e.message}")
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

private fun objectField(s: String, key: String): String? = rawValue(s, key)

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

/** The list of plain quoted strings inside "key": [ "a", "b", ... ]. */
private fun stringArrayField(s: String, key: String): List<String> {
    val raw = rawValue(s, key) ?: return emptyList()
    if (!raw.startsWith("[")) return emptyList()
    val body = raw.substring(1, raw.length - 1)
    return Regex("\"((?:[^\"\\\\]|\\\\.)*)\"").findAll(body).map { it.groupValues[1] }.toList()
}

private fun nullableField(s: String, key: String): String? {
    val m = Regex("\"" + Regex.escape(key) + "\"\\s*:\\s*(null|\"[^\"]*\"|-?[0-9]+|true|false)").find(s) ?: return null
    val raw = m.groupValues[1]
    if (raw == "null") return null
    return if (raw.startsWith("\"")) raw.substring(1, raw.length - 1) else raw
}

private fun strField(s: String, key: String): String =
    nullableField(s, key) ?: throw ChanFailure("string key not found: $key")

private fun intField(s: String, key: String): Long =
    nullableField(s, key)?.toLong() ?: throw ChanFailure("int key not found: $key")

private fun boolField(s: String, key: String): Boolean =
    nullableField(s, key)?.toBoolean() ?: throw ChanFailure("bool key not found: $key")

private fun findVector(rel: String): File {
    var d: File? = File(".").absoluteFile
    repeat(8) {
        val cur = d ?: throw ChanFailure("$rel not found")
        val p = File(cur, rel)
        if (p.isFile) return p
        d = cur.parentFile
    }
    throw ChanFailure("$rel not found from ${File(".").absolutePath}")
}

// ==== channel table vs the independent per-channel oracle (F3, non-circular) ========================

// The twenty channel directory names (lowercase), in TABLE registration order 0x0000..0x0013.
private val CHANNEL_DIRS = listOf(
    "control", "memory", "capability", "identity", "governance", "immune", "federation",
    "settlement", "compliance", "sensory", "telemetry", "audit", "stream", "bridge",
    "commerce", "interaction", "discovery", "workflow", "knowledge", "spatial",
)

private fun tableMatchesOracleRun() {
    for (id in 0..0x13) {
        val dir = CHANNEL_DIRS[id]
        val json = findVector("vectors/channels/$dir/cases.json").readText(Charsets.UTF_8)
        val ch = Channels.channel(id.toLong()) ?: throw ChanFailure("channel $dir (0x%04x)".format(id) + " not registered in Channels")

        katCheck("$dir channel_id == oracle", ch.id.toString(), intField(json, "channel_id").toString())
        katCheck("$dir name == oracle", ch.name, strField(json, "name"))

        val oracleKinds = objectArrayField(json, "kinds")
        katCheck("$dir kind count == oracle", ch.kinds.size.toString(), oracleKinds.size.toString())
        for ((i, kd) in ch.kinds.withIndex()) {
            val ok = oracleKinds[i]
            katCheck("$dir kind[$i].code == oracle", kd.code.toString(), intField(ok, "code").toString())
            katCheck("$dir kind[$i].name == oracle", kd.name, strField(ok, "name"))
            katCheck("$dir kind[$i].effect == oracle", kd.effect.toString(), intField(ok, "effect").toString())
            katCheckBool("$dir kind[$i].variable == oracle", kd.variable, boolField(ok, "variable"))
        }

        val oracleTransitions = objectArrayField(json, "transitions")
        katCheck("$dir transition count == oracle", ch.transitions.size.toString(), oracleTransitions.size.toString())
        for ((i, tr) in ch.transitions.withIndex()) {
            val ot = oracleTransitions[i]
            katCheck("$dir transition[$i].from == oracle", tr.first, strField(ot, "from"))
            katCheck("$dir transition[$i].to == oracle", tr.second, strField(ot, "to"))
        }

        katCheck("$dir states == oracle", ch.states.joinToString(","), stringArrayField(json, "states").joinToString(","))
        katCheck("$dir errors == oracle", ch.errors.joinToString(","), stringArrayField(json, "errors").joinToString(","))
    }
}

// ==== completeness: all twenty channels present, none thinned (R-11.1/R-11.2) ======================

private fun completenessRun() {
    for (id in 0..0x13) {
        val ch = Channels.channel(id.toLong())
        if (ch == null) {
            katFail("channel 0x%04x registered".format(id), "channel(id) returned null")
            continue
        }
        katOk("channel 0x%04x registered".format(id))
        katCheckBool("${ch.name} has at least one kind", ch.kinds.isNotEmpty(), true)
        for (kd in ch.kinds) {
            katCheckBool("${ch.name}.${kd.name} effect in range", kd.effect in 0..3, true)
        }
    }
    // an unregistered channel id returns null, mirroring Go channels.Channel.
    katCheckBool("unregistered channel 0x00FF returns null", Channels.channel(0x00FF) == null, true)
}

// ==== AllowedTransition: representative accept/reject cases (mirrors Go TestStateMachine) ==========

private fun stateMachineRun() {
    data class Case(val ch: Long, val from: String, val to: String, val ok: Boolean)
    val cases = listOf(
        Case(0x0001, "offered", "accepted", true),      // Memory
        Case(0x0001, "live", "revoked", true),           // Memory
        Case(0x0001, "revoked", "live", false),          // Memory regression
        Case(0x000E, "order", "fulfil", true),           // Commerce
        Case(0x000E, "offer", "fulfil", false),          // Commerce skip
        Case(0x0011, "awaiting-input", "running", true), // Workflow
        Case(0x0011, "created", "running", false),       // Workflow gate skip
    )
    for (c in cases) {
        val got = Channels.allowedTransition(c.ch, c.from, c.to)
        katCheckBool("channel 0x%04x %s->%s allowed".format(c.ch, c.from, c.to), got, c.ok)
    }
}

// ==== CheckFrameTree: valid tree accepted, cyclic tree rejected TransformCycle (Spatial §20) ========

private fun frameTreeRun() {
    val tree = mapOf("base" to "", "arm" to "base", "hand" to "arm")
    katExpectOk("valid frame tree accepted") { Channels.checkFrameTree(tree) }

    val cyclic = mapOf("a" to "b", "b" to "c", "c" to "a")
    katExpectThrows("cyclic frame tree rejected", "TransformCycle") { Channels.checkFrameTree(cyclic) }
}

// ==== Workflow input gate: the crash test that InputGateBypass cannot occur (design-channels §18) ==

private fun workflowGateInputBypassRun() {
    val wal = File.createTempFile("naalp-wf", ".wal").also { it.deleteOnExit() }
    wal.delete() // OpenWorkflowGate creates it; start from a genuinely-absent path like Go's t.TempDir()+"wf".

    val g = Channels.openWorkflowGate(wal.absolutePath)
    g.create("t1", false)

    // *** mutation anchor: running before input is supplied MUST be InputGateBypass. Neutering the
    // *** fail-closed branch in WorkflowGate.run flips this assertion from PASS to FAIL.
    katExpectThrows("task cannot run before its input gate", "InputGateBypass") { g.run("t1") }

    // Simulate a crash right after create(): close() flushes and closes the WAL; reopening recovers
    // the pre-gate durable status rather than bypassing it.
    g.close()
    val g2 = Channels.openWorkflowGate(wal.absolutePath)
    katCheck("crash recovers the pre-gate status", g2.status("t1") ?: "<null>", "awaiting-input")
    katExpectThrows("task cannot run after a crash without passing the gate", "InputGateBypass") { g2.run("t1") }

    // Supplying input opens the gate; only then may it run.
    katExpectOk("supplyInput opens the gate") { g2.supplyInput("t1") }
    katExpectOk("task runs after input is supplied") { g2.run("t1") }
    katCheck("status after run", g2.status("t1") ?: "<null>", "running")
    g2.close()

    wal.delete()
}

fun main() {
    println("ChannelsKatTest (Kotlin) — C10 channel state machine + Workflow input gate (design-channels.md)")
    tableMatchesOracleRun()
    completenessRun()
    stateMachineRun()
    frameTreeRun()
    workflowGateInputBypassRun()
    println(if (katFails == 0) "ChannelsKatTest: PASS" else "ChannelsKatTest: FAIL ($katFails)")
    if (katFails != 0) kotlin.system.exitProcess(1)
}
