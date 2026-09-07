// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// #165 stream.state 8-port fan-out — the stream state-machine Guard for the Swift SDK (design.md §10
// state table + § Timers; naalp-error code 49). Mirrors impl/go/streaming/state_guard_test.go's 7
// mutation-surviving tests exactly, translated to Swift/XCTest idiom. The Guard is PURE control logic
// (no ML-DSA, no signatures), so these tests build/run with ANY Swift toolchain regardless of the
// ML-DSA-unavailable condition the rest of this SDK's crypto surface carries.
//
// Written test-first: Streaming.Guard is absent until the Guard lands in Streaming.swift, so this
// fails RED with a compile error ("cannot find 'Guard' in scope" / "type 'Streaming' has no member
// 'newGuard'"). The load-bearing mutation: making Guard.expire not set the state to .abandoned flips
// testGuardExpireAbandonsOpenStream (the terminal state is never entered, so every post-expire event
// assertion fails).
//
// Run:  swift test --filter StreamGuardTests

import XCTest
@testable import Naalp

final class StreamGuardTests: XCTestCase {

    /// Asserts `run` throws a NaalpError with the given kind. Mirrors state_guard_test.go's wantKind.
    static func assertKind(_ run: @autoclosure () throws -> Void, _ kind: String, _ msg: String = "",
                            file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try run(), msg, file: file, line: line) {
            guard let e = $0 as? NaalpError else {
                XCTFail("want \(kind), got non-NaalpError \($0)", file: file, line: line)
                return
            }
            XCTAssertEqual(e.kind, kind, "want \(kind), got \(e.kind)", file: file, line: line)
        }
    }

    // 1. Drives forbidden (state, event) pairs from the stream state table (design.md §10) and asserts
    //    each is rejected StreamStateError. Every case is either a table row whose reaction is
    //    "reject (StreamStateError)" or falls under the table's "any (state, event) pair not listed
    //    above is rejected with StreamStateError" default.
    func testGuardRejectsForbiddenTransitions() throws {
        let sid = Array("stream-forbidden".utf8)

        // idle + chunk -> unlisted pair, default StreamStateError.
        do {
            let g = Streaming.newGuard()
            Self.assertKind(try g.chunk(sid), "StreamStateError", "chunk_before_open")
            XCTAssertEqual(g.state(sid), .idle, "a rejected event must not change state")
        }
        // idle + StreamCheckpoint -> unlisted pair, default StreamStateError.
        do {
            let g = Streaming.newGuard()
            Self.assertKind(try g.checkpoint(sid), "StreamStateError", "checkpoint_before_open")
            XCTAssertEqual(g.state(sid), .idle, "a rejected event must not change state")
        }
        // idle + StreamCommit -> unlisted pair, default StreamStateError.
        do {
            let g = Streaming.newGuard()
            Self.assertKind(try g.commit(Streaming.StreamCommit(streamID: sid, digest: []), []), "StreamStateError",
                             "commit_before_open")
            XCTAssertEqual(g.state(sid), .idle, "a rejected event must not change state")
        }

        // open + StreamOpen -> reject (StreamStateError) — explicit table row.
        do {
            let id = Array("stream-double-open".utf8)
            let g = Streaming.newGuard()
            let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
            XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "first open should succeed")
            Self.assertKind(try g.open(open, Policy.IDEMPOTENT_WRITE), "StreamStateError", "double_open")
            XCTAssertEqual(g.state(id), .open, "a rejected re-open must not change state")
        }

        // committed + {chunk, StreamCheckpoint, StreamCommit, StreamOpen} — the first three are explicit
        // table rows ("reject (StreamStateError)"); StreamOpen-after-committed is the unlisted-pair
        // default.
        do {
            let id = Array("stream-after-commit".utf8)
            let g = Streaming.newGuard()
            let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
            XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "open")
            let chunks = [Streaming.Chunk(offset: 0, data: Array("payload".utf8))]
            let commit = Streaming.StreamCommit(streamID: id, digest: Streaming.commitDigest(chunks))
            XCTAssertNoThrow(try g.commit(commit, chunks), "commit")
            XCTAssertEqual(g.state(id), .committed, "stream should be committed")

            Self.assertKind(try g.chunk(id), "StreamStateError", "events_after_commit: chunk")
            Self.assertKind(try g.checkpoint(id), "StreamStateError", "events_after_commit: checkpoint")
            Self.assertKind(try g.commit(commit, chunks), "StreamStateError", "events_after_commit: commit")
            Self.assertKind(try g.open(open, Policy.IDEMPOTENT_WRITE), "StreamStateError", "events_after_commit: open")

            XCTAssertEqual(g.state(id), .committed, "rejected post-commit events must not change state")
        }
    }

    // 2. The false-positive check: an ordered open -> chunk -> checkpoint -> commit sequence must
    //    succeed and drive the state idle -> open -> committed — the guard must not reject events the
    //    stream state table actually admits.
    func testGuardValidSequenceSucceeds() throws {
        let id = Array("stream-valid".utf8)
        let g = Streaming.newGuard()

        XCTAssertEqual(g.state(id), .idle, "an unopened stream should be idle")

        let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
        XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "open should succeed")
        XCTAssertEqual(g.state(id), .open, "after open, state should be open")

        let chunks = [
            Streaming.Chunk(offset: 0, data: Array("hello ".utf8)),
            Streaming.Chunk(offset: 6, data: Array("world".utf8)),
        ]
        for (i, _) in chunks.enumerated() {
            XCTAssertNoThrow(try g.chunk(id), "chunk \(i) should succeed")
        }
        XCTAssertNoThrow(try g.checkpoint(id), "checkpoint should succeed")
        XCTAssertEqual(g.state(id), .open, "chunks/checkpoint must keep the stream open")

        let commit = Streaming.StreamCommit(streamID: id, digest: Streaming.commitDigest(chunks))
        XCTAssertNoThrow(try g.commit(commit, chunks), "commit should succeed")
        XCTAssertEqual(g.state(id), .committed, "after commit, state should be committed")
    }

    // 3. Distinguishes the guard's ordering check from the existing digest check: "open | StreamCommit
    //    (digest mismatch) | reject (StreamDigestMismatch)" must surface StreamDigestMismatch, not
    //    StreamStateError, and must leave the stream open (the row rejects without advancing) so a
    //    corrected commit still lands.
    func testGuardDigestMismatchIsNotStateError() throws {
        let id = Array("stream-bad-digest".utf8)
        let g = Streaming.newGuard()
        let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
        XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "open")
        let chunks = [Streaming.Chunk(offset: 0, data: Array("payload".utf8))]

        let bad = Streaming.StreamCommit(streamID: id, digest: Array("not-the-real-digest-not-the-real-digest".utf8))
        Self.assertKind(try g.commit(bad, chunks), "StreamDigestMismatch")
        XCTAssertEqual(g.state(id), .open, "a digest-mismatched commit must leave the stream open")

        let good = Streaming.StreamCommit(streamID: id, digest: Streaming.commitDigest(chunks))
        XCTAssertNoThrow(try g.commit(good, chunks), "the corrected commit should still succeed")
        XCTAssertEqual(g.state(id), .committed, "after the corrected commit, state should be committed")
    }

    // 4. "idle | StreamOpen (effect not authorized) | reject (EffectNotAuthorized)" must surface
    //    EffectNotAuthorized, not StreamStateError, and must leave the stream idle so a properly
    //    authorized open on the same stream id still succeeds (R-10.3).
    func testGuardEffectNotAuthorizedLeavesIdle() throws {
        let id = Array("stream-unauthorized".utf8)
        let g = Streaming.newGuard()

        let destructive = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.DESTRUCTIVE), approval: nil, substream: 0)
        Self.assertKind(try g.open(destructive, Policy.READ_ONLY), "EffectNotAuthorized")
        XCTAssertEqual(g.state(id), .idle, "an unauthorized open must leave the stream idle")

        let authorized = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
        XCTAssertNoThrow(try g.open(authorized, Policy.IDEMPOTENT_WRITE), "the authorized open should still succeed")
        XCTAssertEqual(g.state(id), .open, "after the authorized open, state should be open")
    }

    // 5. The guard is keyed by stream id, so one stream's state never leaks into another's.
    func testGuardIndependentStreamsDoNotInterfere() throws {
        let g = Streaming.newGuard()
        let a = Array("stream-a".utf8)
        let b = Array("stream-b".utf8)

        let openA = Streaming.StreamOpen(streamID: a, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
        XCTAssertNoThrow(try g.open(openA, Policy.IDEMPOTENT_WRITE), "open a")
        // b was never opened; any event on b is still rejected StreamStateError even though a is open.
        Self.assertKind(try g.chunk(b), "StreamStateError")
        XCTAssertNoThrow(try g.chunk(a), "chunk on the open stream a should succeed")
    }

    // 6. Drives the idle/commit timer's expiry (§ Timers): Expire on an open stream transitions it
    //    "open -> abandoned", a terminal state that then rejects every event with StreamStateError —
    //    including a StreamOpen reusing the id, so an abandoned stream is never re-admitted. This is
    //    the fail-closed retention that stops a replayed signed StreamOpen from re-opening an
    //    abandoned id. MUTATION TARGET.
    func testGuardExpireAbandonsOpenStream() throws {
        let id = Array("stream-abandoned".utf8)
        let g = Streaming.newGuard()
        let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
        XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "open")

        XCTAssertNoThrow(try g.expire(id), "expiring an open stream should succeed")
        XCTAssertEqual(g.state(id), .abandoned, "after expiry, state should be abandoned")

        // An abandoned stream admits nothing — chunk, checkpoint, commit, and a StreamOpen reusing the
        // id are all rejected StreamStateError (the id is never re-admitted).
        let chunks = [Streaming.Chunk(offset: 0, data: Array("payload".utf8))]
        let commit = Streaming.StreamCommit(streamID: id, digest: Streaming.commitDigest(chunks))
        Self.assertKind(try g.chunk(id), "StreamStateError")
        Self.assertKind(try g.checkpoint(id), "StreamStateError")
        Self.assertKind(try g.commit(commit, chunks), "StreamStateError")
        Self.assertKind(try g.open(open, Policy.IDEMPOTENT_WRITE), "StreamStateError")

        XCTAssertEqual(g.state(id), .abandoned, "rejected post-abandon events must not change state")
    }

    // 7. The idle/commit timer clears when a StreamCommit transitions the stream to committed
    //    (§ Timers), so a correct caller fires Expire only while the stream is open. Expire on an idle,
    //    committed, or already-abandoned stream is therefore rejected StreamStateError and leaves the
    //    state unchanged (fail-closed).
    func testGuardExpireOnNonOpenIsStateError() throws {
        // idle: nothing has been opened.
        do {
            let id = Array("stream-expire-idle".utf8)
            let g = Streaming.newGuard()
            Self.assertKind(try g.expire(id), "StreamStateError", "idle")
            XCTAssertEqual(g.state(id), .idle, "expiring an idle stream must not change state")
        }

        // committed: the timer should have cleared on commit; a spurious Expire is a state error and
        // must not turn a committed (non-repudiable) stream into an abandoned one.
        do {
            let id = Array("stream-expire-committed".utf8)
            let g = Streaming.newGuard()
            let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
            XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "open")
            let chunks = [Streaming.Chunk(offset: 0, data: Array("payload".utf8))]
            let commit = Streaming.StreamCommit(streamID: id, digest: Streaming.commitDigest(chunks))
            XCTAssertNoThrow(try g.commit(commit, chunks), "commit")
            Self.assertKind(try g.expire(id), "StreamStateError", "committed")
            XCTAssertEqual(g.state(id), .committed, "expiring a committed stream must not change state")
        }

        // already abandoned: a second Expire is a state error and a no-op.
        do {
            let id = Array("stream-expire-twice".utf8)
            let g = Streaming.newGuard()
            let open = Streaming.StreamOpen(streamID: id, effect: UInt64(Policy.IDEMPOTENT_WRITE), approval: nil, substream: 0)
            XCTAssertNoThrow(try g.open(open, Policy.IDEMPOTENT_WRITE), "open")
            XCTAssertNoThrow(try g.expire(id), "first expire")
            Self.assertKind(try g.expire(id), "StreamStateError", "already_abandoned")
            XCTAssertEqual(g.state(id), .abandoned, "a second expire must not change state")
        }
    }
}
