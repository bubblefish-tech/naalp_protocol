// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Stream chunk-count decoder resource bound (design.md §3.4, R7) for the Swift SDK, mirroring
// impl/go/streaming/bounds_test.go.
//
// Run:  swift test --package-path impl/swift --filter StreamingBoundsTests

import XCTest
@testable import Naalp

final class StreamingBoundsTests: XCTestCase {

    /// Pins the stream chunk-count bound (design.md §3.4, R7): a commit over exactly
    /// MAX_STREAM_CHUNKS chunks verifies, and one over MAX_STREAM_CHUNKS+1 is rejected
    /// TooManyChunks. Both carry a MATCHING rolling digest, so the count is the only reason to
    /// reject -- deleting the count check makes the +1 case verify (the mutation is caught). The
    /// chunks share one empty-data value to bound test memory. MUTATION TARGET.
    func testBoundTooManyChunks() throws {
        let over = [Streaming.Chunk](repeating: Streaming.Chunk(offset: 0, data: []), count: Int(MAX_STREAM_CHUNKS) + 1)
        let atLimit = Array(over[0..<Int(MAX_STREAM_CHUNKS)])

        let okCommit = Streaming.StreamCommit(streamID: [], digest: Streaming.commitDigest(atLimit))
        XCTAssertNoThrow(try Streaming.verifyCommit(okCommit, atLimit),
                         "commit over \(MAX_STREAM_CHUNKS) chunks should verify")

        let overCommit = Streaming.StreamCommit(streamID: [], digest: Streaming.commitDigest(over))
        XCTAssertThrowsError(try Streaming.verifyCommit(overCommit, over),
                             "commit over \(MAX_STREAM_CHUNKS + 1) chunks should be TooManyChunks") { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "TooManyChunks")
        }

        // VerifyCheckpoint enforces the same bound, and the count check fires before the
        // contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
        let cp = Streaming.StreamCheckpoint(streamID: [], throughOffset: 0, digestSoFar: [])
        XCTAssertThrowsError(try Streaming.verifyCheckpoint(cp, over),
                             "checkpoint over \(MAX_STREAM_CHUNKS + 1) chunks should be TooManyChunks") { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "TooManyChunks")
        }
    }
}
