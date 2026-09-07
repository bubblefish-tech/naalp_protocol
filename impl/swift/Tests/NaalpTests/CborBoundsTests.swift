// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// CBOR decoder nesting-depth bound (design.md §3.4, R7) for the Swift SDK, mirroring
// impl/go/cbor/bounds_test.go and impl/rust/src/cbor.rs's bound tests byte-for-byte in shape.
//
// Run:  swift test --package-path impl/swift --filter CborBoundsTests

import XCTest
@testable import Naalp

final class CborBoundsTests: XCTestCase {

    /// Returns canonical CBOR for k single-element arrays wrapping a zero scalar: 0x81 (array of
    /// one) repeated k times, then 0x00. Decoding it, the outermost array is at depth 1 and the
    /// innermost scalar is at depth k+1.
    static func nestedArraysCBOR(_ k: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0x81, count: k)
        b.append(0x00)
        return b
    }

    /// Pins the nesting-depth counter (design.md §3.4, R7): the outermost item is depth 1, and
    /// decodeBounded rejects the first item at depth maxDepth+1 with a DepthExceeded error, before
    /// it is materialized. The unbounded decode(_:) path still accepts the same structure, so the
    /// bound -- not another check -- is what does the work. MUTATION TARGET.
    func testDecodeBoundedDepth() throws {
        let d = 3

        // deepest scalar at depth d (k = d-1): accepted at maxDepth=d.
        let atLimit = Self.nestedArraysCBOR(d - 1)
        XCTAssertNoThrow(try Cbor.decodeBounded(atLimit, d),
                         "deepest item at depth \(d) should decode at maxDepth=\(d)")

        // deepest scalar at depth d+1 (k = d): rejected DepthExceeded at maxDepth=d.
        let over = Self.nestedArraysCBOR(d)
        XCTAssertThrowsError(try Cbor.decodeBounded(over, d),
                             "deepest item at depth \(d + 1) should be DepthExceeded at maxDepth=\(d)") { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "DepthExceeded")
        }

        // The unbounded path accepts the same over-depth structure: the bound, not another check,
        // is what rejected it above.
        XCTAssertNoThrow(try Cbor.decode(over), "unbounded decode should accept the depth-\(d + 1) structure")
    }
}
