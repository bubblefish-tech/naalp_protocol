// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import kotlin.system.exitProcess

/**
 * Stream state-guard known-answer tests for the Kotlin SDK, mirroring
 * impl/go/streaming/state_guard_test.go (design.md §10 state table + § Timers): the Guard enforces
 * idle -> open -> committed, with abandoned as the terminal state an open stream enters on the
 * idle/commit timer's expiry, rejecting an event the table does not admit for the stream's current
 * state with StreamStateError before any state change.
 *
 * KAT convention: a standalone main() exiting non-zero on any failure; the filename carries the
 * "Tests" token the ten-language-parity gate indexes.
 *
 * Mutation anchors: each of the 7 cases below pins a distinct row (or unlisted-pair default) of the
 * stream state table; a mutation admitting a forbidden transition, or one that stops abandoning /
 * committing on a valid transition, flips exactly the case(s) that exercise that row.
 */

private var sgFails = 0

private fun sgCheck(name: String, got: String, want: String) {
    if (got == want) {
        println("  ok   $name")
    } else {
        sgFails++
        println("  FAIL $name\n       got  $got\n       want $want")
    }
}

/** Run [block]; return "ok" if it returns, else the NaalpException kind. */
private fun sgKind(block: () -> Unit): String = try {
    block()
    "ok"
} catch (e: NaalpException) {
    e.kind
}

private fun sgState(g: Streaming.Guard, id: ByteArray): String = g.state(id).toString()

// (a) TestGuardRejectsForbiddenTransitions: forbidden (state, event) pairs from the stream state
// table are rejected StreamStateError, and a rejected event never changes state.
private fun testGuardRejectsForbiddenTransitions() {
    // idle + chunk -> unlisted pair, default StreamStateError.
    run {
        val sid = "stream-forbidden".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        sgCheck("chunk_before_open", sgKind { g.chunk(sid) }, "StreamStateError")
        sgCheck("chunk_before_open state unchanged", sgState(g, sid), "idle")
    }
    // idle + StreamCheckpoint -> unlisted pair, default StreamStateError.
    run {
        val sid = "stream-forbidden".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        sgCheck("checkpoint_before_open", sgKind { g.checkpoint(sid) }, "StreamStateError")
        sgCheck("checkpoint_before_open state unchanged", sgState(g, sid), "idle")
    }
    // idle + StreamCommit -> unlisted pair, default StreamStateError.
    run {
        val sid = "stream-forbidden".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        val kind = sgKind { g.commit(Streaming.StreamCommit(sid, ByteArray(0)), emptyList()) }
        sgCheck("commit_before_open", kind, "StreamStateError")
        sgCheck("commit_before_open state unchanged", sgState(g, sid), "idle")
    }

    // open + StreamOpen -> reject (StreamStateError) -- explicit table row.
    run {
        val id = "stream-double-open".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
        sgCheck("double_open first open succeeds", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")
        sgCheck("double_open", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "StreamStateError")
        sgCheck("double_open state unchanged", sgState(g, id), "open")
    }

    // committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} -- the first three are explicit
    // table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the unlisted-pair
    // default.
    run {
        val id = "stream-after-commit".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
        sgCheck("events_after_commit open", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")
        val chunks = listOf(Streaming.Chunk(0L, "payload".toByteArray(Charsets.UTF_8)))
        val commit = Streaming.StreamCommit(id, Streaming.commitDigest(chunks))
        sgCheck("events_after_commit commit", sgKind { g.commit(commit, chunks) }, "ok")
        sgCheck("events_after_commit committed", sgState(g, id), "committed")

        sgCheck("events_after_commit chunk", sgKind { g.chunk(id) }, "StreamStateError")
        sgCheck("events_after_commit checkpoint", sgKind { g.checkpoint(id) }, "StreamStateError")
        sgCheck("events_after_commit commit again", sgKind { g.commit(commit, chunks) }, "StreamStateError")
        sgCheck("events_after_commit reopen", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "StreamStateError")

        sgCheck("events_after_commit state unchanged", sgState(g, id), "committed")
    }
}

// (b) TestGuardValidSequenceSucceeds: the false-positive check -- an ordered
// open -> chunk -> checkpoint -> commit sequence must succeed and drive the state
// idle -> open -> committed -- the guard must not reject events the stream state table admits.
private fun testGuardValidSequenceSucceeds() {
    val id = "stream-valid".toByteArray(Charsets.UTF_8)
    val g = Streaming.Guard()

    sgCheck("an unopened stream should be idle", sgState(g, id), "idle")

    val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
    sgCheck("open should succeed", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")
    sgCheck("after open, state should be open", sgState(g, id), "open")

    val chunks = listOf(
        Streaming.Chunk(0L, "hello ".toByteArray(Charsets.UTF_8)),
        Streaming.Chunk(6L, "world".toByteArray(Charsets.UTF_8))
    )
    for (i in chunks.indices) {
        sgCheck("chunk $i should succeed", sgKind { g.chunk(id) }, "ok")
    }
    sgCheck("checkpoint should succeed", sgKind { g.checkpoint(id) }, "ok")
    sgCheck("chunks/checkpoint must keep the stream open", sgState(g, id), "open")

    val commit = Streaming.StreamCommit(id, Streaming.commitDigest(chunks))
    sgCheck("commit should succeed", sgKind { g.commit(commit, chunks) }, "ok")
    sgCheck("after commit, state should be committed", sgState(g, id), "committed")
}

// (c) TestGuardDigestMismatchIsNotStateError: distinguishes the guard's ordering check from the
// existing digest check -- "open | StreamCommit (digest mismatch) | reject (StreamDigestMismatch)"
// must surface StreamDigestMismatch, not StreamStateError, and must leave the stream open (the row
// rejects without advancing) so a corrected commit still lands.
private fun testGuardDigestMismatchIsNotStateError() {
    val id = "stream-bad-digest".toByteArray(Charsets.UTF_8)
    val g = Streaming.Guard()
    val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
    sgCheck("open", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")
    val chunks = listOf(Streaming.Chunk(0L, "payload".toByteArray(Charsets.UTF_8)))

    val bad = Streaming.StreamCommit(id, "not-the-real-digest-not-the-real-digest".toByteArray(Charsets.UTF_8))
    sgCheck("digest-mismatched commit rejected", sgKind { g.commit(bad, chunks) }, "StreamDigestMismatch")
    sgCheck("a digest-mismatched commit must leave the stream open", sgState(g, id), "open")

    val good = Streaming.StreamCommit(id, Streaming.commitDigest(chunks))
    sgCheck("the corrected commit should still succeed", sgKind { g.commit(good, chunks) }, "ok")
    sgCheck("after the corrected commit, state should be committed", sgState(g, id), "committed")
}

// (d) TestGuardEffectNotAuthorizedLeavesIdle: "idle | StreamOpen (effect not authorized) | reject
// (EffectNotAuthorized)" must surface EffectNotAuthorized, not StreamStateError, and must leave the
// stream idle so a properly authorized open on the same stream id still succeeds (R-10.3).
private fun testGuardEffectNotAuthorizedLeavesIdle() {
    val id = "stream-unauthorized".toByteArray(Charsets.UTF_8)
    val g = Streaming.Guard()

    val destructive = Streaming.StreamOpen(id, Policy.DESTRUCTIVE, null, 0L)
    sgCheck("unauthorized open refused", sgKind { g.open(destructive, Policy.READ_ONLY) }, "EffectNotAuthorized")
    sgCheck("an unauthorized open must leave the stream idle", sgState(g, id), "idle")

    val authorized = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
    sgCheck("the authorized open should still succeed", sgKind { g.open(authorized, Policy.IDEMPOTENT_WRITE) }, "ok")
    sgCheck("after the authorized open, state should be open", sgState(g, id), "open")
}

// (e) TestGuardIndependentStreamsDoNotInterfere: the guard is keyed by stream id, so one stream's
// state never leaks into another's.
private fun testGuardIndependentStreamsDoNotInterfere() {
    val g = Streaming.Guard()
    val a = "stream-a".toByteArray(Charsets.UTF_8)
    val b = "stream-b".toByteArray(Charsets.UTF_8)

    val openA = Streaming.StreamOpen(a, Policy.IDEMPOTENT_WRITE, null, 0L)
    sgCheck("open a", sgKind { g.open(openA, Policy.IDEMPOTENT_WRITE) }, "ok")
    // b was never opened; any event on b is still rejected StreamStateError even though a is open.
    sgCheck("b still rejected while a is open", sgKind { g.chunk(b) }, "StreamStateError")
    sgCheck("chunk on the open stream a should succeed", sgKind { g.chunk(a) }, "ok")
}

// (f) TestGuardExpireAbandonsOpenStream: drives the idle/commit timer's expiry (§ Timers): Expire on
// an open stream transitions it "open -> abandoned", a terminal state that then rejects every event
// with StreamStateError -- including a StreamOpen reusing the id, so an abandoned stream is never
// re-admitted. This is the fail-closed retention that stops a replayed signed StreamOpen from
// re-opening an abandoned id.
private fun testGuardExpireAbandonsOpenStream() {
    val id = "stream-abandoned".toByteArray(Charsets.UTF_8)
    val g = Streaming.Guard()
    val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
    sgCheck("open", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")

    sgCheck("expiring an open stream should succeed", sgKind { g.expire(id) }, "ok")
    sgCheck("after expiry, state should be abandoned", sgState(g, id), "abandoned")

    // An abandoned stream admits nothing -- chunk, checkpoint, commit, and a StreamOpen reusing the
    // id are all rejected StreamStateError (the id is never re-admitted).
    val chunks = listOf(Streaming.Chunk(0L, "payload".toByteArray(Charsets.UTF_8)))
    val commit = Streaming.StreamCommit(id, Streaming.commitDigest(chunks))
    sgCheck("chunk after abandon", sgKind { g.chunk(id) }, "StreamStateError")
    sgCheck("checkpoint after abandon", sgKind { g.checkpoint(id) }, "StreamStateError")
    sgCheck("commit after abandon", sgKind { g.commit(commit, chunks) }, "StreamStateError")
    sgCheck("reopen after abandon", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "StreamStateError")

    sgCheck("rejected post-abandon events must not change state", sgState(g, id), "abandoned")
}

// (g) TestGuardExpireOnNonOpenIsStateError: the idle/commit timer clears when a StreamCommit
// transitions the stream to committed (§ Timers), so a correct caller fires Expire only while the
// stream is open. Expire on an idle, committed, or already-abandoned stream is therefore rejected
// StreamStateError and leaves the state unchanged (fail-closed).
private fun testGuardExpireOnNonOpenIsStateError() {
    // idle: nothing has been opened.
    run {
        val id = "stream-expire-idle".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        sgCheck("expiring an idle stream must be rejected", sgKind { g.expire(id) }, "StreamStateError")
        sgCheck("expiring an idle stream must not change state", sgState(g, id), "idle")
    }

    // committed: the timer should have cleared on commit; a spurious Expire is a state error and must
    // not turn a committed (non-repudiable) stream into an abandoned one.
    run {
        val id = "stream-expire-committed".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
        sgCheck("open", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")
        val chunks = listOf(Streaming.Chunk(0L, "payload".toByteArray(Charsets.UTF_8)))
        val commit = Streaming.StreamCommit(id, Streaming.commitDigest(chunks))
        sgCheck("commit", sgKind { g.commit(commit, chunks) }, "ok")
        sgCheck("expiring a committed stream must be rejected", sgKind { g.expire(id) }, "StreamStateError")
        sgCheck("expiring a committed stream must not change state", sgState(g, id), "committed")
    }

    // already abandoned: a second Expire is a state error and a no-op.
    run {
        val id = "stream-expire-twice".toByteArray(Charsets.UTF_8)
        val g = Streaming.Guard()
        val open = Streaming.StreamOpen(id, Policy.IDEMPOTENT_WRITE, null, 0L)
        sgCheck("open", sgKind { g.open(open, Policy.IDEMPOTENT_WRITE) }, "ok")
        sgCheck("first expire", sgKind { g.expire(id) }, "ok")
        sgCheck("a second expire must be rejected", sgKind { g.expire(id) }, "StreamStateError")
        sgCheck("a second expire must not change state", sgState(g, id), "abandoned")
    }
}

fun main() {
    println("stream guard conformance (Kotlin) -- state guard (design.md §10 state table + § Timers)")
    testGuardRejectsForbiddenTransitions()
    testGuardValidSequenceSucceeds()
    testGuardDigestMismatchIsNotStateError()
    testGuardEffectNotAuthorizedLeavesIdle()
    testGuardIndependentStreamsDoNotInterfere()
    testGuardExpireAbandonsOpenStream()
    testGuardExpireOnNonOpenIsStateError()
    println(if (sgFails == 0) "StreamGuardTests: PASS" else "StreamGuardTests: FAIL ($sgFails)")
    exitProcess(if (sgFails == 0) 0 else 1)
}
