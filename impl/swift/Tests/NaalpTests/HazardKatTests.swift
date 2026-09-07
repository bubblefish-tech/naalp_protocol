// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Manufacturing Add-ons Component F (naalp-hazard) known-answer test for the Swift SDK, graded
// against the independent, non-circular oracle vectors/hazard/cases.json (tools/hazard_oracle.py)
// -- mirroring impl/rust/naalp-hazard/src/lib.rs's test module and impl/csharp/HazardKatTest.cs,
// i.e. Swift == Rust == Go == C# == oracle.
//
// Run: swift test --package-path impl/swift --filter HazardKatTests

import Foundation
import XCTest
@testable import Naalp

final class HazardKatTests: XCTestCase {

    /// Walk up from this source file to the committed vector (mirrors SignerCounterKatTests /
    /// RecheckKatTests's findVector).
    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/hazard/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    /// A `code`/`class` cell in the oracle is JSON null, a bare JSON number (<= 2^53), or a
    /// QUOTED decimal string (> 2^53, so a float64 JSON decoder cannot round it -- NAALP-01-03).
    /// Read either form as the exact UInt64; nil for JSON null / absent.
    static func numberU64(_ v: Any?) -> UInt64? {
        if let n = v as? NSNumber { return n.uint64Value }
        if let s = v as? String { return UInt64(s) }
        return nil
    }

    static func axesFrom(_ o: [String: Any]) -> [Hazard.Axis] {
        let raw = o["axes"] as! [Any]
        return raw.map { item in
            let pair = item as! [Any]
            let mn = (pair[0] as! NSNumber).int64Value
            let mx = (pair[1] as! NSNumber).int64Value
            return Hazard.Axis(mn, mx)
        }
    }

    static func envFrom(_ o: [String: Any]) -> Hazard.HazardEnvelope {
        let axes = Self.axesFrom(o)
        let spatial = Hazard.SpatialBounds(frame: o["frame"] as! String, axes: axes)
        let speed = (o["speed_bound_mm_s"] as! NSNumber).uint64Value
        let window = Hazard.HazardWindow(
            notBefore: (o["not_before"] as! NSNumber).uint64Value,
            notAfter: (o["not_after"] as! NSNumber).uint64Value)
        return Hazard.HazardEnvelope(spatial: spatial, speedBoundMmS: speed, window: window)
    }

    static func errKind(_ f: () throws -> Void) -> String {
        do {
            try f()
            return "no-error"
        } catch let e as NaalpError {
            return e.kind
        } catch {
            return "unexpected: \(error)"
        }
    }

    // ---- F2: fail-closed class decode (mutation anchor: a constant HazardClass.none return
    // would pass none of the non-zero cases; a constant motionInSharedSpace would fail the exact
    // 0..3 cases). --------------------------------------------------------------------------

    func testFromCodeFailClosedMatchesOracle() throws {
        guard let c = Self.findVector() else {
            throw XCTSkip("committed hazard vector not present (standalone build)")
        }
        guard let rows = c["from_code"] as? [[String: Any]] else {
            XCTFail("corpus has no from_code[] array"); return
        }
        for row in rows {
            let input = Self.numberU64(row["code"])
            let want = (row["class"] as! NSNumber).uint8Value
            XCTAssertEqual(Hazard.HazardClass.fromCode(input).code, want, "from_code(\(String(describing: input)))")
        }
        // Explicit oracle-independent assertions of the two named fail-closed cases (F2).
        XCTAssertEqual(Hazard.HazardClass.fromCode(nil), .motionInSharedSpace, "absent must normalize to the highest class")
        XCTAssertEqual(Hazard.HazardClass.fromCode(9), .motionInSharedSpace, "unknown code must normalize to the highest class")
        XCTAssertEqual(Hazard.HazardClass.fromCode(UInt64.max), .motionInSharedSpace, "an out-of-range code must still normalize, not panic or wrap")

        // The five in-range codes decode to themselves, never collapsing to the default.
        for code in UInt64(0)...4 {
            XCTAssertEqual(UInt64(Hazard.HazardClass.fromCode(code).code), code)
        }
    }

    // ---- byte-level: encode matches the independent oracle (=> Swift == Go == Rust == C#). ----

    func testClaimAndAuthorizationBytesMatchOracle() throws {
        guard let c = Self.findVector() else {
            throw XCTSkip("committed hazard vector not present (standalone build)")
        }
        guard let rows = c["bodies"] as? [[String: Any]] else {
            XCTFail("corpus has no bodies[] array"); return
        }
        for row in rows {
            let name = row["name"] as? String ?? "?"
            let cls = Hazard.HazardClass.fromCode(Self.numberU64(row["class"]))
            let e = Self.envFrom(row)
            let claim = Hazard.HazardClaim(hazardClass: cls, envelope: e)
            let auth = Hazard.HazardAuthorization(hazardClass: cls, envelope: e)
            let want = row["body_hex"] as! String
            XCTAssertEqual(try WorkedExampleTests.toHex(claim.bytes()), want, "\(name): claim bytes")
            XCTAssertEqual(try WorkedExampleTests.toHex(auth.bytes()), want, "\(name): authorization bytes (same shape as claim)")
            XCTAssertEqual(try WorkedExampleTests.toHex(claim.contentId()), row["content_id_hex"] as! String, "\(name): content-id")
        }
    }

    // Round-trip: fromValue(toValue(x)) == x for every oracle body.
    func testRoundTripMatchesOracle() throws {
        guard let c = Self.findVector() else {
            throw XCTSkip("committed hazard vector not present (standalone build)")
        }
        guard let rows = c["bodies"] as? [[String: Any]] else {
            XCTFail("corpus has no bodies[] array"); return
        }
        for row in rows {
            let name = row["name"] as? String ?? "?"
            let cls = Hazard.HazardClass.fromCode(Self.numberU64(row["class"]))
            let e = Self.envFrom(row)
            let claim = Hazard.HazardClaim(hazardClass: cls, envelope: e)
            let got = try Hazard.HazardClaim.fromValue(claim.toValue())
            XCTAssertEqual(got, claim, "round-trip \(name)")
        }
    }

    // ---- F3: coverage matrix (mutation anchor: a constant "no throw" fails the deny rows; a
    // constant "always throw" fails the allow rows) ------------------------------------------

    func testCoverageMatchesOracle() throws {
        guard let c = Self.findVector() else {
            throw XCTSkip("committed hazard vector not present (standalone build)")
        }
        guard let rows = c["coverage"] as? [[String: Any]] else {
            XCTFail("corpus has no coverage[] array"); return
        }
        XCTAssertFalse(rows.isEmpty)
        var allows = 0
        var denies = 0
        for row in rows {
            let name = row["name"] as? String ?? "?"
            let claim = Hazard.HazardClaim(
                hazardClass: Hazard.HazardClass.fromCode(Self.numberU64(row["claim_class_code"])),
                envelope: Self.envFrom(row["claim_envelope"] as! [String: Any]))
            let grant = Hazard.HazardAuthorization(
                hazardClass: Hazard.HazardClass.fromCode(Self.numberU64(row["grant_class_code"])),
                envelope: Self.envFrom(row["grant_envelope"] as! [String: Any]))
            let wantOk = row["authorized"] as! Bool
            if wantOk {
                allows += 1
                XCTAssertNoThrow(try Hazard.hazardAuthorized(claim, grant), "\(name): want authorized")
            } else {
                denies += 1
                XCTAssertThrowsError(try Hazard.hazardAuthorized(claim, grant), "\(name): want denied") { error in
                    XCTAssertEqual((error as? NaalpError)?.kind, "HazardNotCovered", name)
                }
            }
        }
        XCTAssertTrue(allows > 0 && denies > 0, "matrix needs both allows and denies")
    }

    // F2/F4's "absent hazard" behavioural vector, at the OBJECT level (no claim at all): distinct
    // from an in-range-but-mismatched class, and distinct from an unrecognized class byte inside
    // a present claim (covered by testCoverageMatchesOracle's normalized rows).
    func testAbsentClaimDeniesWithDistinctError() throws {
        let grant = Hazard.HazardAuthorization(
            hazardClass: .toolActuation,
            envelope: Hazard.HazardEnvelope(
                spatial: Hazard.SpatialBounds(frame: "cell-7/world", axes: [Hazard.Axis(0, 1000), Hazard.Axis(0, 1000), Hazard.Axis(0, 500)]),
                speedBoundMmS: 500,
                window: Hazard.HazardWindow(notBefore: 0, notAfter: 1000)))

        XCTAssertThrowsError(try Hazard.hazardAuthorizedOptional(nil, grant), "an absent claim must never authorize") { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "HazardUnknown")
        }

        // A present, well-covered claim still authorizes through the same entry point.
        let claim = Hazard.HazardClaim(
            hazardClass: .toolActuation,
            envelope: Hazard.HazardEnvelope(
                spatial: Hazard.SpatialBounds(frame: "cell-7/world", axes: [Hazard.Axis(100, 200), Hazard.Axis(100, 200), Hazard.Axis(0, 100)]),
                speedBoundMmS: 100,
                window: Hazard.HazardWindow(notBefore: 10, notAfter: 900)))
        XCTAssertNoThrow(try Hazard.hazardAuthorizedOptional(claim, grant))
    }

    // ---- structural malformation (fail-closed, never partially valid) -------------------------

    func testMalformedBodiesRejected() throws {
        // empty axes
        let bad = Hazard.SpatialBounds(frame: "f", axes: [])
        XCTAssertFalse(bad.isWellFormed())
        XCTAssertEqual(Self.errKind { _ = try Hazard.SpatialBounds.fromValue(bad.toValue()) }, "HazardMalformed")

        // min > max
        let bad2 = Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(10, -10)])
        XCTAssertFalse(bad2.isWellFormed())

        // non-NFC frame ('e' + combining acute, NFD not NFC)
        let bad3 = Hazard.SpatialBounds(frame: "e\u{0301}", axes: [Hazard.Axis(0, 1)])
        XCTAssertFalse(bad3.isWellFormed())

        // wrong shape entirely (not a map)
        XCTAssertEqual(Self.errKind { _ = try Hazard.HazardClaim.fromValue(.u(0)) }, "HazardMalformed")

        // class present, envelope missing
        let partial: CborValue = .m([(.u(1), .u(1))])
        XCTAssertEqual(Self.errKind { _ = try Hazard.HazardClaim.fromValue(partial) }, "HazardMalformed")

        // an explicit out-of-range class ON THE WIRE (not "absent") is malformed, not silently
        // normalized -- see hazardBodyFromValue's doc comment.
        let goodEnv = Hazard.HazardEnvelope(
            spatial: Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(0, 1)]),
            speedBoundMmS: 1,
            window: Hazard.HazardWindow(notBefore: 0, notAfter: 1)).toValue()
        let outOfRange: CborValue = .m([(.u(1), .u(99)), (.u(2), goodEnv)])
        XCTAssertEqual(Self.errKind { _ = try Hazard.HazardClaim.fromValue(outOfRange) }, "HazardMalformed")
    }

    // ---- containment truth table (independent of the oracle file, direct assertions) ----------

    func testSpatialContainedTruthTable() {
        let grant = Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(0, 100), Hazard.Axis(0, 100)])
        // fully inside -> contained
        let inside = Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(10, 90), Hazard.Axis(10, 90)])
        XCTAssertTrue(Hazard.spatialContained(inside, grant))
        // equal bounds -> contained (closed interval)
        let equal = Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(0, 100), Hazard.Axis(0, 100)])
        XCTAssertTrue(Hazard.spatialContained(equal, grant))
        // one axis pokes outside -> not contained
        let outside = Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(10, 90), Hazard.Axis(10, 101)])
        XCTAssertFalse(Hazard.spatialContained(outside, grant))
        // different frame -> never contained regardless of numeric bounds
        let wrongFrame = Hazard.SpatialBounds(frame: "g", axes: [Hazard.Axis(10, 90), Hazard.Axis(10, 90)])
        XCTAssertFalse(Hazard.spatialContained(wrongFrame, grant))
        // fewer axes -> never contained
        let fewer = Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(10, 90)])
        XCTAssertFalse(Hazard.spatialContained(fewer, grant))
    }

    func testEnvelopeContainedWindowAndSpeed() {
        func env(_ lo: Int64, _ hi: Int64, _ speed: UInt64, _ nb: UInt64, _ na: UInt64) -> Hazard.HazardEnvelope {
            Hazard.HazardEnvelope(spatial: Hazard.SpatialBounds(frame: "f", axes: [Hazard.Axis(lo, hi)]),
                                   speedBoundMmS: speed, window: Hazard.HazardWindow(notBefore: nb, notAfter: na))
        }
        let grant = env(0, 100, 500, 100, 900)
        let ok = env(0, 100, 500, 100, 900) // exact edges, closed interval
        XCTAssertTrue(Hazard.envelopeContained(ok, grant))
        let speedOver = env(0, 100, 501, 100, 900)
        XCTAssertFalse(Hazard.envelopeContained(speedOver, grant))
        let startsEarly = env(0, 100, 500, 99, 900)
        XCTAssertFalse(Hazard.envelopeContained(startsEarly, grant))
        let endsLate = env(0, 100, 500, 100, 901)
        XCTAssertFalse(Hazard.envelopeContained(endsLate, grant))
    }
}
