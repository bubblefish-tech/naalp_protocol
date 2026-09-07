// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C9 native streaming with a single signed per-stream commitment for the Swift SDK (design.md §10;
// R-10.1..10.6), graded against the shared independent corpus vectors/stream/cases.json (NOTE: the module
// is named `streaming` but the oracle directory is `stream`, matching Go/Python). Values come from the
// corpus, NEVER from this code.
//
// A native stream is three signed objects plus unsigned chunks: StreamOpen establishes the stream's
// identity, effect, and (where it causes an effect) its approval binding, refusing a stream whose effect
// is not authorized BEFORE any chunk (§10.2, R-10.3); the chunks are raw data frames the transport AEAD
// already authenticates, so N-AALP does NOT sign them individually (R-10.2); StreamCommit carries a rolling
// SHA-384 over the chunks in absolute-offset order, making the whole stream non-repudiable with ONE
// signature, not N (§10.2). Optional signed StreamCheckpoints let a verifier confirm a prefix without the
// end. Altering any delivered byte invalidates the commitment (StreamDigestMismatch).
//
// CORPUS-GRADED (pure, signature-independent): the rolling SHA-384 commitment, the mid-stream checkpoints,
// the StreamOpen/Commit/Checkpoint bodies, the tamper digest, the order-independence (reversed input, same
// digest) + position-dependence (swapped offsets, different digest), and the R-10.3 effect ceiling.
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the ONE end-commitment signature over the
// StreamCommit body — a RAW deterministic signature over the body (matching impl/go/streaming's raw
// SignCommit, NOT a COSE_Sign1 assembly) — demonstrated with real Ed25519 (RFC 8032) via swift-crypto; the
// reference's commitment signature is ML-DSA (FIPS 204), NOT reproducible in the pure tier (SwiftDilithium
// 3.6.0) and NOT faked. SINGLE-THREAD NOTE (honest F2/F4): the reference's R-10.5 full-duplex test runs two
// streams concurrently under -race; this pure-tier port demonstrates the byte-level commitment properties
// single-threaded (distinct streams -> distinct commitments), which is the signature-independent surface
// the corpus grades.
//
// Written test-first: Naalp.Streaming is absent until Streaming.swift lands, so this fails RED with a
// compile error ("cannot find 'Streaming' in scope"). The load-bearing mutation: making verifyCommit accept
// unconditionally (skip the digest comparison) flips "tampered stream rejected (StreamDigestMismatch)" in
// testTamperInvalidatesCommit.
//
// Run:  swift test --filter StreamingTests

import XCTest
@testable import Naalp

final class StreamingTests: XCTestCase {

    static func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    static func toHex(_ b: [UInt8]) -> String {
        let d = Array("0123456789abcdef")
        var s = ""
        for x in b { s.append(d[Int(x >> 4)]); s.append(d[Int(x & 0x0f)]) }
        return s
    }

    static func u64(_ v: Any?) throws -> UInt64 {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").uint64Value
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/stream/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func loadVector() throws -> [String: Any] {
        guard let v = findVector() else {
            throw XCTSkip("vectors/stream/cases.json not present (standalone build)")
        }
        return v
    }

    static func chunksOf(_ c: [String: Any]) throws -> [Streaming.Chunk] {
        return try XCTUnwrap(c["chunks"] as? [[String: Any]]).map { ch in
            Streaming.Chunk(offset: try u64(ch["offset"]), data: hexToBytes(try XCTUnwrap(ch["data_hex"] as? String)))
        }
    }

    static func streamKey(_ label: String) throws -> (seed: [UInt8], pk: [UInt8]) {
        let seed = Array(Cbor.contentId(Array("naalp-stream-key:\(label)".utf8)).dropFirst(2).prefix(32))
        return (seed, try Cose.ed25519PublicKey(seed))
    }

    // 1. the rolling commitment, the mid-stream checkpoints, and the StreamOpen/Commit/Checkpoint bodies all
    //    equal the independent oracle (⟹ Go == Rust == Python == Swift).
    func testDigestAndBodiesMatchOracle() throws {
        let c = try Self.loadVector()
        let streamID = Self.hexToBytes(try XCTUnwrap(c["stream_id_hex"] as? String))
        let chunks = try Self.chunksOf(c)
        let finalHex = try XCTUnwrap(c["final_digest_hex"] as? String)

        XCTAssertEqual(Self.toHex(Streaming.commitDigest(chunks)), finalHex, "final digest == oracle")

        // Rolling: DigestSoFar after each chunk equals the checkpoint, and the last equals final.
        let checkpoints = try XCTUnwrap(c["checkpoints"] as? [[String: Any]])
        var sd = Streaming.StreamDigest()
        for (i, ch) in chunks.enumerated() {
            sd.update(ch.data)
            if i < checkpoints.count {
                XCTAssertEqual(Self.toHex(sd.digestSoFar()), checkpoints[i]["digest_so_far_hex"] as? String,
                               "checkpoint \(i) rolling digest == oracle")
            }
        }
        XCTAssertEqual(Self.toHex(sd.digestSoFar()), finalHex, "rolling final == oracle")

        let open = Streaming.StreamOpen(streamID: streamID, effect: try Self.u64(c["effect"]),
                                        approval: Self.hexToBytes(try XCTUnwrap(c["approval_hex"] as? String)),
                                        substream: try Self.u64(c["substream"]))
        XCTAssertEqual(Self.toHex(try open.bytes()), c["open_body_hex"] as? String, "StreamOpen body == oracle")
        let commit = Streaming.StreamCommit(streamID: streamID, digest: Self.hexToBytes(finalHex))
        XCTAssertEqual(Self.toHex(try commit.bytes()), c["commit_body_hex"] as? String, "StreamCommit body == oracle")
        let cp0 = Streaming.StreamCheckpoint(streamID: streamID, throughOffset: try Self.u64(checkpoints[0]["through_offset"]),
                                             digestSoFar: Self.hexToBytes(try XCTUnwrap(checkpoints[0]["digest_so_far_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try cp0.bytes()), c["checkpoint_body_hex"] as? String, "StreamCheckpoint body == oracle")
    }

    // 2. R-10.2 — the correct stream verifies; altering one delivered byte invalidates the commitment
    //    (StreamDigestMismatch), and the tampered stream's digest equals the oracle's tamper digest
    //    (non-circular: the flipped bytes and their digest both come from the corpus). MUTATION TARGET.
    func testTamperInvalidatesCommit() throws {
        let c = try Self.loadVector()
        let streamID = Self.hexToBytes(try XCTUnwrap(c["stream_id_hex"] as? String))
        let finalHex = try XCTUnwrap(c["final_digest_hex"] as? String)
        let chunks = try Self.chunksOf(c)
        let commit = Streaming.StreamCommit(streamID: streamID, digest: Self.hexToBytes(finalHex))

        XCTAssertNoThrow(try Streaming.verifyCommit(commit, chunks), "the valid stream verifies")

        let tamper = try XCTUnwrap(c["tamper"] as? [String: Any])
        var tampered = try Self.chunksOf(c)
        let idx = Int(try Self.u64(tamper["chunk_index"]))
        tampered[idx] = Streaming.Chunk(offset: tampered[idx].offset,
                                        data: Self.hexToBytes(try XCTUnwrap(tamper["flipped_data_hex"] as? String)))
        XCTAssertEqual(Self.toHex(Streaming.commitDigest(tampered)), tamper["digest_hex"] as? String,
                       "tampered-stream digest == oracle tamper digest")
        XCTAssertThrowsError(try Streaming.verifyCommit(commit, tampered), "tampered stream rejected (StreamDigestMismatch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "StreamDigestMismatch")
        }
    }

    // 3. a checkpoint confirms a prefix without the end; a prefix whose length does not match the checkpoint
    //    is rejected.
    func testCheckpointVerifiesPrefix() throws {
        let c = try Self.loadVector()
        let streamID = Self.hexToBytes(try XCTUnwrap(c["stream_id_hex"] as? String))
        let all = try Self.chunksOf(c)
        let checkpoints = try XCTUnwrap(c["checkpoints"] as? [[String: Any]])
        for (i, cpj) in checkpoints.enumerated() {
            let cp = Streaming.StreamCheckpoint(streamID: streamID, throughOffset: try Self.u64(cpj["through_offset"]),
                                                digestSoFar: Self.hexToBytes(try XCTUnwrap(cpj["digest_so_far_hex"] as? String)))
            let prefix = Array(all[0...i]) // chunks through this checkpoint, WITHOUT the end
            XCTAssertNoThrow(try Streaming.verifyCheckpoint(cp, prefix), "checkpoint \(i) verifies its prefix")
        }
        // A checkpoint claiming the first prefix but given the full stream fails (wrong length).
        let cp0 = Streaming.StreamCheckpoint(streamID: streamID, throughOffset: try Self.u64(checkpoints[0]["through_offset"]),
                                             digestSoFar: Self.hexToBytes(try XCTUnwrap(checkpoints[0]["digest_so_far_hex"] as? String)))
        XCTAssertThrowsError(try Streaming.verifyCheckpoint(cp0, all), "wrong-length prefix rejected (StreamDigestMismatch)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "StreamDigestMismatch")
        }
    }

    // 4. R-10.3 — a stream whose effect exceeds the granted capability is refused at open, before any chunk;
    //    the corpus stream (idempotent_write) under an idempotent_write grant is authorized; an unrecognized
    //    effect fails closed to destructive and is refused.
    func testEffectRefusedBeforeChunk() throws {
        let c = try Self.loadVector()
        let streamID = Self.hexToBytes(try XCTUnwrap(c["stream_id_hex"] as? String))
        let destructive = Streaming.StreamOpen(streamID: streamID, effect: UInt64(Policy.DESTRUCTIVE), approval: nil, substream: 1)
        XCTAssertThrowsError(try Streaming.openStream(destructive, Policy.READ_ONLY),
                             "destructive stream under read-only grant refused (EffectNotAuthorized)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "EffectNotAuthorized")
        }
        let ok = Streaming.StreamOpen(streamID: streamID, effect: try Self.u64(c["effect"]),
                                      approval: Self.hexToBytes(try XCTUnwrap(c["approval_hex"] as? String)),
                                      substream: try Self.u64(c["substream"]))
        XCTAssertNoThrow(try Streaming.openStream(ok, Policy.IDEMPOTENT_WRITE), "authorized stream may open")
        let unknown = Streaming.StreamOpen(streamID: streamID, effect: 99, approval: nil, substream: 1)
        XCTAssertThrowsError(try Streaming.openStream(unknown, Policy.NON_IDEMPOTENT_WRITE),
                             "unknown effect fails closed to destructive and is refused") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "EffectNotAuthorized")
        }
    }

    // 5. CommitDigest is over absolute-offset order — input order is irrelevant, but swapping which data
    //    sits at which offset changes the commitment.
    func testOffsetOrderMatters() throws {
        let c = try Self.loadVector()
        let chunks = try Self.chunksOf(c)
        let reversed = Array(chunks.reversed())
        XCTAssertEqual(Self.toHex(Streaming.commitDigest(chunks)), Self.toHex(Streaming.commitDigest(reversed)),
                       "reversed input yields the same digest (sorted by offset)")
        var swapped = try Self.chunksOf(c)
        let d0 = swapped[0].data, d1 = swapped[1].data
        swapped[0] = Streaming.Chunk(offset: swapped[0].offset, data: d1)
        swapped[1] = Streaming.Chunk(offset: swapped[1].offset, data: d0)
        XCTAssertNotEqual(Self.toHex(Streaming.commitDigest(swapped)), try XCTUnwrap(c["final_digest_hex"] as? String),
                          "swapping data across offsets changes the digest")
    }

    // 6. the ONE end-commitment signature over the StreamCommit body, demonstrated in isolation with real
    //    Ed25519 (raw signature over the body): a well-signed commitment verifies; a tampered signature does
    //    not. (The reference commitment signature is ML-DSA, not reproducible pure-tier and not faked.)
    func testSignedCommitmentEd25519() throws {
        let c = try Self.loadVector()
        let streamID = Self.hexToBytes(try XCTUnwrap(c["stream_id_hex"] as? String))
        let commit = Streaming.StreamCommit(streamID: streamID, digest: Self.hexToBytes(try XCTUnwrap(c["final_digest_hex"] as? String)))
        let key = try Self.streamKey("owner")
        let sig = try Streaming.signCommit(commit, key.seed)
        XCTAssertTrue(Cose.ed25519Verify(key.pk, try commit.bytes(), sig), "Ed25519-signed commitment verifies")
        var bad = sig; bad[0] ^= 0x01
        XCTAssertFalse(Cose.ed25519Verify(key.pk, try commit.bytes(), bad), "tampered commitment signature does not verify")
    }
}
