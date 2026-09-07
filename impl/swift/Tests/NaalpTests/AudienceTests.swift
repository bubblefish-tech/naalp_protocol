// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// The object-audience (field 13, §2.5.3) known-answer + gate tests for the Swift SDK.
//
// Three properties, all mutation-surviving:
//   1. BYTE MATCH -- an audience-bearing object reproduces the independent oracle's content id,
//      payload, protected header, and to-be-signed bytes (vectors/envelope/cases.json
//      object_with_audience), and a NO-audience object reproduces the base object.content_id_hex --
//      proving omit-when-empty additivity byte-for-byte (Swift == Go == Rust == ... == the oracle).
//      These are the PURE bytes (signingInputs), computed from object fields alone -- no ML-DSA.
//   2. checkAudience -- the three-branch point-of-use gate.
//   3. consumeObject -- enforced at the consume choke point BEFORE the compare-and-set: wrong/absent
//      -> WrongAudience with no append; unnamed ledger -> LedgerUnsigned; correct -> consumes once.
//
// Run:  swift test --package-path impl/swift

import XCTest
@testable import Naalp

final class AudienceTests: XCTestCase {

    static let SIGNER = WorkedExampleTests.hexToBytes("5349474e45525f41") // "SIGNER_A"
    static let AUDIENCE = "consuming-authority-xyz"

    static func hex(_ b: [UInt8]) -> String { WorkedExampleTests.toHex(b) }

    static func audienceObject() -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: SIGNER, created: 1785000000000,
                        effect: 2, body: .t("hello"), tier: 0, profile: 1, audience: AUDIENCE)
    }

    static func plainObject() -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: SIGNER, created: 1785000000000,
                        effect: 2, body: .t("hello"), tier: 0, profile: 1)
    }

    static func gateObject(_ aud: String) -> Envelope.Object {
        Envelope.Object(kind: 2, channel: 4, signer: SIGNER, created: 0, effect: 0,
                        body: .t("x"), tier: 0, profile: 1, audience: aud)
    }

    static func findEnvelopeVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/envelope/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    func testAudienceBytesReproduceOracle() throws {
        guard let root = Self.findEnvelopeVector(),
              let want = root["object_with_audience"] as? [String: Any],
              let base = root["object"] as? [String: Any] else {
            throw XCTSkip("committed oracle vector not present (standalone build)")
        }
        var obj = Self.audienceObject()
        let inputs = try Envelope.signingInputs(&obj, Cose.ALG_MLDSA65)
        XCTAssertEqual(Self.hex(try obj.contentId()), want["content_id_hex"] as? String, "content id")
        XCTAssertEqual(Self.hex(inputs.payload), want["payload_hex"] as? String, "payload")
        XCTAssertEqual(Self.hex(inputs.protected), want["protected_hex"] as? String, "protected header")
        XCTAssertEqual(Self.hex(inputs.toBeSigned), want["tobesigned_hex"] as? String, "to-be-signed")

        // omit-when-empty additivity: a no-audience object reproduces the BASE draft-00 content id
        XCTAssertEqual(Self.hex(try Self.plainObject().contentId()), base["content_id_hex"] as? String, "plain content id")
        XCTAssertNotEqual(Self.hex(try Self.audienceObject().contentId()),
                          Self.hex(try Self.plainObject().contentId()), "audience changes the identity")
    }

    func testCheckAudienceBranches() throws {
        // passes (no throw)
        try Envelope.checkAudience(Self.gateObject("authority-A"), "authority-A", true)
        try Envelope.checkAudience(Self.gateObject(""), "authority-A", false)
        try Envelope.checkAudience(Self.gateObject("authority-A"), "authority-A", false)
        // rejects
        for (aud, once) in [("authority-B", true), ("", true), ("authority-B", false)] {
            XCTAssertThrowsError(try Envelope.checkAudience(Self.gateObject(aud), "authority-A", once)) { error in
                XCTAssertEqual((error as? NaalpError)?.kind, "WrongAudience")
            }
        }
    }

    private func withLedger(_ authority: String, _ body: (Approval.Ledger) throws -> Void) throws {
        // a unique WAL per invocation (UUID, not #line -- #line is constant here and would collide
        // across the cases, which fails under parallel XCTest).
        let path = NSTemporaryDirectory() + "naalp-audience-\(UUID().uuidString).wal"
        try? FileManager.default.removeItem(atPath: path)
        let led = try Approval.Ledger.open(path, authority: authority)
        defer { try? led.close(); try? FileManager.default.removeItem(atPath: path) }
        try body(led)
    }

    private func aid() -> [UInt8] { (0..<50).map { UInt8($0) } }

    func testConsumeObjectWrongAudienceNoAppend() throws {
        try withLedger("authority-A") { led in
            XCTAssertThrowsError(try led.consumeObject(Self.gateObject("authority-B"), self.aid(), "consumer")) { error in
                XCTAssertEqual((error as? NaalpError)?.kind, "WrongAudience")
            }
            XCTAssertEqual(led.len(), 0, "a rejected consume MUST NOT append a ledger entry")
        }
    }

    func testConsumeObjectAbsentAudienceNoAppend() throws {
        try withLedger("authority-A") { led in
            XCTAssertThrowsError(try led.consumeObject(Self.gateObject(""), self.aid(), "consumer")) { error in
                XCTAssertEqual((error as? NaalpError)?.kind, "WrongAudience")
            }
            XCTAssertEqual(led.len(), 0)
        }
    }

    func testConsumeObjectCorrectAudienceConsumesOnce() throws {
        try withLedger("authority-A") { led in
            try led.consumeObject(Self.gateObject("authority-A"), self.aid(), "consumer")
            XCTAssertEqual(led.len(), 1)
            XCTAssertThrowsError(try led.consumeObject(Self.gateObject("authority-A"), self.aid(), "consumer")) { error in
                XCTAssertEqual((error as? NaalpError)?.kind, "AlreadyConsumed")
            }
        }
    }

    func testConsumeObjectUnnamedLedgerRefuses() throws {
        try withLedger("") { led in
            XCTAssertThrowsError(try led.consumeObject(Self.gateObject("authority-A"), self.aid(), "consumer")) { error in
                XCTAssertEqual((error as? NaalpError)?.kind, "LedgerUnsigned")
            }
        }
    }
}
