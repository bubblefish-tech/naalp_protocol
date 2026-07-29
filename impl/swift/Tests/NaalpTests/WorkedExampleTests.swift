// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The full-object known-answer test for the Swift SDK's PURE envelope surface. The reference
// worked object (fixed seed 0x2a*32, ML-DSA-65) MUST be reproduced byte-for-byte on the pure
// surface: its content id, its encoded body payload, and its COSE ToBeSigned bytes are computed
// from the object fields alone, and the tagged COSE_Sign1 assembled from the object's own
// protected header + payload and the committed ML-DSA signature MUST equal the committed
// signed_object_hex. (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204 path, so the
// ML-DSA *signature* itself is brought in from the committed vector, not produced here; every
// byte around it is produced by this SDK.) The structural verify pipeline is also exercised
// end-to-end up to the skip-tracked ML-DSA crypto boundary, and tampering is rejected.
//
// Run:  swift test --package-path impl/swift

import XCTest
@testable import Naalp

final class WorkedExampleTests: XCTestCase {

    static let SIGNER_ID = "bciqmqbeciwpwrbuv4j2ldnf2araohpsnsy6rfidj3kcrroy6tl222ua"
    static let ARGS_ID_HEX = "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff"
    static let CONTENT_ID_HEX = "2030192922f9be80623bea1c689ddfe91dc15303abc851c8811b86cf9e53b837b5cc99d9c17e3acf95279f55e48203f79134"

    static func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(s.count / 2)
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

    /// Build the exact worked object (Governance Approval, channel 4, kind 1, Public profile).
    static func workedObject() -> Envelope.Object {
        let body = CborValue.m([
            (.u(1), .b(hexToBytes(ARGS_ID_HEX))),
            (.u(2), .t(SIGNER_ID)),
            (.u(3), .u(2)),
            (.u(4), .b([1, 2, 3, 4, 5, 6, 7, 8])),
            (.u(5), .u(1785000000000)),
        ])
        return Envelope.Object(kind: 1, channel: 4, signer: Array(SIGNER_ID.utf8),
                               created: 1785000000000, effect: 2, body: body, tier: 0,
                               profile: UInt64(Cose.PROFILE_PUBLIC))
    }

    /// Walk up from this source file to find the committed vector (mirrors the Python/TS tests).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/worked/example.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    func testContentIdReproducesKAT() throws {
        let obj = Self.workedObject()
        XCTAssertEqual(Self.toHex(try obj.contentId()), Self.CONTENT_ID_HEX)
    }

    func testPureBytesReproduceCommittedVector() throws {
        guard let want = Self.findVector() else {
            throw XCTSkip("committed vector not present (standalone build)")
        }
        var obj = Self.workedObject()
        let inputs = try Envelope.signingInputs(&obj, Cose.ALG_MLDSA65)

        XCTAssertEqual(Self.toHex(try obj.contentId()), want["content_id_hex"] as? String)
        XCTAssertEqual(Self.toHex(inputs.payload), want["payload_body_hex"] as? String)
        XCTAssertEqual(Self.toHex(inputs.toBeSigned), want["to_be_signed_hex"] as? String)
        XCTAssertEqual(Self.toHex(inputs.protected), want["protected_hdr_hex"] as? String)
    }

    func testAssembleSignedReproducesCommittedObject() throws {
        guard let want = Self.findVector(),
              let signedHex = want["signed_object_hex"] as? String else {
            throw XCTSkip("committed vector not present (standalone build)")
        }
        // Recover the committed ML-DSA signature from the committed object, then re-assemble
        // from THIS SDK's own protected header + payload and assert the full bytes match.
        let (_, _, committedSig) = try Cose.parseSign1Raw(Self.hexToBytes(signedHex))
        XCTAssertEqual(committedSig.count, 3309, "committed ML-DSA-65 signature length")

        var obj = Self.workedObject()
        let assembled = try Envelope.assembleSigned(&obj, Cose.ALG_MLDSA65, committedSig)
        XCTAssertEqual(Self.toHex(assembled), signedHex)
    }

    func testStructuralVerifyReachesMLDSABoundary() throws {
        // The worked object passes every structural check; only the ML-DSA signature step is
        // skip-tracked, so verify() throws `Unavailable` (proving the whole pipeline ran).
        guard let want = Self.findVector(),
              let signedHex = want["signed_object_hex"] as? String else {
            throw XCTSkip("committed vector not present (standalone build)")
        }
        let signed = Self.hexToBytes(signedHex)
        let pk = [UInt8](repeating: 0, count: 1952)  // ML-DSA-65 pk shape (unused: crypto skip-tracked)
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk,
                                { c, k in c == 4 && k == 1 }, signed)
        ) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Unavailable")
        }
    }

    func testStructuralVerifyRejectsTamperedContentId() throws {
        guard let want = Self.findVector(),
              let signedHex = want["signed_object_hex"] as? String else {
            throw XCTSkip("committed vector not present (standalone build)")
        }
        // Flip a byte inside the payload's content-id field. This must be caught by the
        // content-id recomputation BEFORE the signature step (a structural, crypto-free check).
        var signed = Self.hexToBytes(signedHex)
        // The content id sits early in the object; locate the first 0x30 marker of the id bstr
        // header (58 32 ...) inside the assembled object and corrupt a payload byte deep enough
        // to land in the content-id value. We corrupt the object at a fixed payload offset by
        // re-assembling a tampered object instead, which is deterministic.
        let (_, _, committedSig) = try Cose.parseSign1Raw(signed)
        var obj = Self.workedObject()
        obj.effect = 2
        _ = try Envelope.assembleSigned(&obj, Cose.ALG_MLDSA65, committedSig)
        // Now build a genuinely mismatched object: keep the committed id-bearing payload but
        // change a body field so the recomputed id differs. Easiest deterministic route: mutate
        // a raw payload byte in the assembled bytes within the body region and assert
        // ContentIdMismatch.
        // Corrupt the last byte of the payload's created field region by flipping a byte at a
        // stable offset just after the content id (offset chosen to be within the body, not the
        // signature). We instead assert via a rebuilt object below.
        _ = signed  // (kept for clarity; direct-offset tampering is covered by the rebuild path)

        // Rebuild path: an object whose claimed id (committed) will not match a changed body.
        // Assemble a DIFFERENT object with the committed signature; its recomputed id differs
        // from the id embedded by assembleSigned? No — assembleSigned recomputes the id. So to
        // force a mismatch we hand-craft bytes: take the committed object and flip one byte of
        // the signer-id text inside the body (which changes the recomputed id but not the
        // embedded claimed id, because we edit the raw bytes after assembly).
        var tampered = try Envelope.assembleSigned(&obj, Cose.ALG_MLDSA65, committedSig)
        // find the ascii 'b' of the first signer-id occurrence in the body (field 5) and flip it
        if let idx = tampered.firstIndex(of: UInt8(ascii: "q")) {
            tampered[idx] = UInt8(ascii: "r")
        }
        let pk = [UInt8](repeating: 0, count: 1952)
        XCTAssertThrowsError(
            try Envelope.verify(Cose.PROFILE_PUBLIC, Cose.ALG_MLDSA65, pk,
                                { _, _ in true }, tampered)
        ) { error in
            // Editing a body byte changes the recomputed content id while the embedded claimed
            // id is unchanged -> ContentIdMismatch (a structural failure before any crypto).
            XCTAssertEqual((error as? NaalpError)?.kind, "ContentIdMismatch")
        }
    }
}
