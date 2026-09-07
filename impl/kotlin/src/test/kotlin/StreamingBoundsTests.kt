// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

/**
 * Stream chunk-count bound (design.md §3.4, R7) known-answer test for the Kotlin SDK, mirroring
 * impl/go/streaming/bounds_test.go: a commit over exactly MAX_STREAM_CHUNKS chunks verifies, and
 * one over MAX_STREAM_CHUNKS+1 is rejected TooManyChunks. Both carry a MATCHING rolling digest, so
 * the count is the only reason to reject -- deleting the count check makes the +1 case verify (the
 * mutation is caught). The chunks share offset 0 with empty data (a preallocated cheap accept-at-
 * limit case, mirroring Go's zero-value chunk slice) so building MAX_STREAM_CHUNKS+1 of them stays
 * fast.
 *
 * Run (main()-driven, no test framework):
 *   kotlinc src/main/kotlin src/test/kotlin/StreamingBoundsTests.kt -cp <bcprov.jar> -include-runtime -d out/streaming-bounds.jar
 *   java -cp "out/streaming-bounds.jar;<bcprov.jar>" sh.bubblefish.naalp.StreamingBoundsTestsKt
 */

private class StreamingBoundsFailure(msg: String) : RuntimeException(msg)

private fun sbOk(what: String) = println("  ok  $what")

private val SB_EMPTY = ByteArray(0)

/** n zero-offset, empty-data chunks: trivially contiguous (each satisfies offset==runningTotal==0),
 *  so the same list serves both the commit and the checkpoint boundary checks. */
private fun sbZeroChunks(n: Int): List<Streaming.Chunk> = List(n) { Streaming.Chunk(0L, SB_EMPTY) }

/** Run [block]; return "ok" if it returns, else the NaalpException kind. */
private fun sbVerifyKind(block: () -> Unit): String = try {
    block()
    "ok"
} catch (e: NaalpException) {
    e.kind
}

// TestBoundTooManyChunks pins the stream chunk-count bound (design.md §3.4, R7): a commit over
// exactly MAX_STREAM_CHUNKS chunks verifies, and one over MAX_STREAM_CHUNKS+1 is rejected
// TooManyChunks.
private fun testBoundTooManyChunks() {
    val overCount = (MAX_STREAM_CHUNKS + 1L).toInt()
    val over = sbZeroChunks(overCount)
    val atLimit = over.subList(0, MAX_STREAM_CHUNKS.toInt())

    val okCommit = Streaming.StreamCommit(SB_EMPTY, Streaming.commitDigest(atLimit))
    val okKind = sbVerifyKind { Streaming.verifyCommit(okCommit, atLimit) }
    if (okKind != "ok") throw StreamingBoundsFailure("commit over $MAX_STREAM_CHUNKS chunks should verify, got $okKind")
    sbOk("commit at MaxStreamChunks verifies")

    val overCommit = Streaming.StreamCommit(SB_EMPTY, Streaming.commitDigest(over))
    val overKind = sbVerifyKind { Streaming.verifyCommit(overCommit, over) }
    if (overKind != "TooManyChunks") {
        throw StreamingBoundsFailure("commit over ${MAX_STREAM_CHUNKS + 1L} chunks should be TooManyChunks, got $overKind")
    }
    sbOk("commit over MaxStreamChunks rejected TooManyChunks")

    // VerifyCheckpoint enforces the same bound, and the count check fires before the
    // contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
    val cpKind = sbVerifyKind {
        Streaming.verifyCheckpoint(Streaming.StreamCheckpoint(SB_EMPTY, 0L, SB_EMPTY), over)
    }
    if (cpKind != "TooManyChunks") {
        throw StreamingBoundsFailure("checkpoint over ${MAX_STREAM_CHUNKS + 1L} chunks should be TooManyChunks, got $cpKind")
    }
    sbOk("checkpoint over MaxStreamChunks rejected TooManyChunks (count checked before digest)")
}

fun main() {
    println("StreamingBoundsTests -- stream chunk-count bound (design.md §3.4, R7)")
    testBoundTooManyChunks()
    println("StreamingBoundsTests: PASS")
}
