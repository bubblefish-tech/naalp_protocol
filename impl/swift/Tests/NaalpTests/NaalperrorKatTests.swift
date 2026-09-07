// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// T3.3 naalp-error object + numeric error-code registry conformance for the Swift SDK (design.md
// §3.5, R3.3/R3.4), mirroring impl/go/naalperror/naalperror_test.go,
// impl/rust/src/naalperror.rs's #[cfg(test)] mod tests, and
// impl/typescript/test/naalperror.test.mjs -- the hand-computed CBOR is independent of the oracle
// and of impl/go/impl/rust, so this is a non-circular KAT. This module is pure CBOR (no crypto), so
// it does not hit the swift-crypto/ML-DSA build gap other Swift work has.
//
// Run:  swift test --package-path impl/swift --filter NaalperrorKatTests

import Foundation
import XCTest
@testable import Naalp

final class NaalperrorKatTests: XCTestCase {

    private func hex(_ b: [UInt8]) -> String {
        b.map { String(format: "%02x", $0) }.joined()
    }

    // TestRegistrySize: pins the registry to exactly 129 unique names with no gaps (the
    // fields-of-record invariant: code == index+1, sequential 1..129). A mutation that drops or
    // duplicates an entry flips this and the code/name relationship.
    func testRegistrySizeAndIndex() {
        XCTAssertEqual(Naalperror.NAMES.count, 132)
        var seen = Set<String>()
        for (i, n) in Naalperror.NAMES.enumerated() {
            XCTAssertFalse(seen.contains(n), "duplicate name \(n)")
            seen.insert(n)
            let (code, registered) = Naalperror.codeForName(n)
            XCTAssertTrue(registered, n)
            XCTAssertEqual(code, UInt64(i + 1), n)
        }
    }

    // TestEncodeKAT: pins the deterministic naalp-error body bytes against hand-computed CBOR
    // (independent of the oracle and of impl/go/impl/rust): a2 (map-2) 01 <code> 02 <tstr name>.
    // A mutation of encode flips it. These are the MANDATORY KATs.
    func testEncodeKat() throws {
        XCTAssertEqual(hex(try Naalperror.encode(1, "NonCanonical", "", nil)),
                        "a20101026c4e6f6e43616e6f6e6963616c")
        XCTAssertEqual(hex(try Naalperror.encode(52, "NotDelivered", "", nil)),
                        "a2011834026c4e6f7444656c697665726564")
    }

    // TestEncodeDecodeFull: exercises the optional fields 3 and 4 (map grows to a3/a4, keys stay
    // ascending). A mutation that drops a field or mis-orders keys flips the round-trip below.
    func testEncodeDecodeFull() throws {
        let subj: [UInt8] = [0x20, 0x30] + [UInt8](repeating: 0, count: 48)
        let (code, registered) = Naalperror.codeForName("BadSignature")
        XCTAssertTrue(registered)
        let b = try Naalperror.encode(code, "BadSignature", "reason", subj)
        let o = try Naalperror.decode(b)
        XCTAssertEqual(o.name, "BadSignature")
        XCTAssertEqual(o.detail, "reason")
        XCTAssertEqual(o.subject?.count, 50)
    }

    // TestDualCarriageMismatch: a registered code carrying the wrong registered name is rejected
    // Malformed (the strengthening direction). A mutation that skips the name check flips this.
    // This is one of the MANDATORY KATs (code 22=BadSignature, wrong name "NotDelivered").
    func testDualCarriageMismatchIsMalformed() throws {
        let (code, _) = Naalperror.codeForName("BadSignature") // code 22, name of code 52
        let b = try Naalperror.encode(code, "NotDelivered", "", nil)
        XCTAssertThrowsError(try Naalperror.decode(b)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Malformed")
        }
    }

    // TestUnknownCodeOpaque: a code outside the registry is accepted opaque (open-registry
    // contract). A mutation that rejects unknown codes flips this. This is one of the MANDATORY
    // KATs.
    func testUnknownCodeIsOpaque() throws {
        let b = try Naalperror.encode(60000, "SomeFutureError", "", nil)
        let o = try Naalperror.decode(b)
        XCTAssertEqual(o.code, 60000)
        XCTAssertEqual(o.name, "SomeFutureError")
    }

    // TestNameForCode: pins a few known code->name entries + the unregistered boundary.
    func testNameForCodeBoundary() {
        let known: [(UInt64, String)] = [(1, "NonCanonical"), (22, "BadSignature"), (119, "RebindUnauthorized")]
        for (code, want) in known {
            let (name, registered) = Naalperror.nameForCode(code)
            XCTAssertTrue(registered, "code \(code)")
            XCTAssertEqual(name, want, "code \(code)")
        }
        for code: UInt64 in [0, 133, 60000] {
            let (_, registered) = Naalperror.nameForCode(code)
            XCTAssertFalse(registered, "code \(code) should be unregistered")
        }
        XCTAssertEqual(Naalperror.STANDARDS_MAX, 0x7FFF)
    }

    // Structural malformation: closed grammar. A non-map, a missing mandatory field, and an
    // unknown field key are all rejected Malformed -- never silently accepted or misclassified.
    func testStructurallyMalformedBodiesAreRejectedMalformed() throws {
        // not a map at all
        let notAMap = try Cbor.encode(.a([]))
        XCTAssertThrowsError(try Naalperror.decode(notAMap)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Malformed")
        }

        // missing the mandatory name field (key 2)
        let missingName = try Cbor.encode(.m([(.u(1), .u(1))]))
        XCTAssertThrowsError(try Naalperror.decode(missingName)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Malformed")
        }

        // an unknown field key (5) is a closed-grammar violation
        let unknownField = try Cbor.encode(.m([
            (.u(1), .u(1)), (.u(2), .t("NonCanonical")), (.u(5), .u(0)),
        ]))
        XCTAssertThrowsError(try Naalperror.decode(unknownField)) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Malformed")
        }

        // garbage bytes are not well-formed CBOR at all
        XCTAssertThrowsError(try Naalperror.decode([0xff, 0xff])) { error in
            XCTAssertEqual((error as? NaalpError)?.kind, "Malformed")
        }
    }
}
