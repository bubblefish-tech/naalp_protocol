// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C11 transport-binding conformance for the Swift SDK, graded against the shared independent
// corpus vectors/transport/cases.json (NOT produced by this code): the media type, the six
// binding variants' confidentiality/peer-auth guarantees, the framing round-trip, and the
// §12.3/§12.4 emit-boundary matrix. Every property below is a PURE deterministic assertion (no
// crypto), so all of transport is corpus-graded on the pure Swift port.
//
// Written test-first: the Naalp.Transport type is absent until Transport.swift lands, so this
// fails RED with a compile error on the first reference; a mutation to the emit boundary flips
// the "emit websocket+ws sensitive" row.
//
// Run:  swift test --filter TransportTests

import XCTest
@testable import Naalp

final class TransportTests: XCTestCase {

    /// Walk up from this source file to find the committed corpus (mirrors WorkedExampleTests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/transport/cases.json")
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
            throw XCTSkip("vectors/transport/cases.json not present (standalone build)")
        }
        return v
    }

    // 1. media type is the one-object-per-representation N-AALP type (§12.1).
    func testMediaTypeMatchesOracle() throws {
        let c = try Self.loadVector()
        XCTAssertEqual(Transport.MEDIA_TYPE, c["media_type"] as? String)
    }

    // 2. every transport variant's confidentiality/peer-auth guarantees == the oracle.
    func testVariantGuaranteesMatchOracle() throws {
        let c = try Self.loadVector()
        let variants = try XCTUnwrap(c["transports"] as? [[String: Any]])
        for t in variants {
            let name = try XCTUnwrap(t["name"] as? String)
            let want = try XCTUnwrap(Transport.byName(name), "variant present: \(name)")
            XCTAssertEqual(want.confidential, t["confidential"] as? Bool,
                           "variant confidentiality: \(name)")
            XCTAssertEqual(want.peerAuthenticated, t["peer_authenticated"] as? Bool,
                           "variant peer-auth: \(name)")
        }
        // an unknown binding name has no variant.
        XCTAssertNil(Transport.byName("carrier-pigeon"), "unknown transport is absent")
    }

    // 3. framing round-trips the object bytes verbatim; the media type is the N-AALP type (R-13.2).
    func testFrameRoundTrip() throws {
        let np = try XCTUnwrap(Transport.byName("npamp"))
        let mu = Transport.frame(np, [0x01, 0x02, 0x03])
        XCTAssertEqual(mu.mediaType, Transport.MEDIA_TYPE, "frame media type")
        XCTAssertEqual(mu.transport, "npamp", "frame transport name")
        XCTAssertEqual(try mu.object(), [0x01, 0x02, 0x03], "frame roundtrip object")
    }

    // 4. a message unit with a wrong media type is rejected Malformed (fail-closed).
    func testWrongMediaTypeRejected() throws {
        let bad = Transport.MessageUnit(transport: "npamp", mediaType: "application/json",
                                        payload: [0x78])
        XCTAssertThrowsError(try bad.object()) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Malformed", "wrong media type rejected")
        }
    }

    // 5. the §12.3 confidentiality / §12.4 peer-auth emit-boundary matrix == the oracle, row by row.
    func testEmitMatrixMatchesOracle() throws {
        let c = try Self.loadVector()
        let matrix = try XCTUnwrap(c["emit_matrix"] as? [[String: Any]])
        let objBytes = Array("obj".utf8)
        for row in matrix {
            let name = try XCTUnwrap(row["transport"] as? String)
            let sensitive = try XCTUnwrap(row["sensitive"] as? Bool)
            let requirePeerAuth = try XCTUnwrap(row["require_peer_auth"] as? Bool)
            let wantResult = try XCTUnwrap(row["result"] as? String)
            let t = try XCTUnwrap(Transport.byName(name))
            let label = "emit \(name) sensitive=\(sensitive ? 1 : 0) peer=\(requirePeerAuth ? 1 : 0)"

            var got = "no-error"
            do {
                let unit = try Transport.emit(t, objBytes, sensitive, requirePeerAuth)
                // on success the framed unit must carry the object bytes unchanged.
                got = (try unit.object() == objBytes) ? "ok" : "framed-wrong-bytes"
            } catch let e as NaalpError {
                got = e.kind
            }
            XCTAssertEqual(got, wantResult, label)
        }
    }
}
