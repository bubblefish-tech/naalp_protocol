// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C5 §6 authorization for the Swift SDK: the granted×effect authorize/deny matrix (R-6.3), the
// signature-only authorization-principal rule (R-6.5), and the strict optional safety-label
// extraction (R-6.4). Graded against the shared independent corpus vectors/effect/cases.json
// (values from the corpus, NEVER produced by this code): the authorization_matrix, principal_sources,
// and safety_label sections.

import XCTest
@testable import Naalp

final class PolicyTests: XCTestCase {

    static func loadVector() throws -> [String: Any] {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            let p = dir.appendingPathComponent("vectors/effect/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        throw NaalpError("VectorMissing", "vectors/effect/cases.json not found")
    }

    // R-6.3: the endpoint policy check denies exactly the effects exceeding the grant's ceiling (a
    // matched signature principal), and the raw lattice agrees. THE MUTATION TARGET: making
    // Grant.authorizeObject accept everything flips the denied rows here on their EffectNotAuthorized.
    func testAuthorizationMatrix() throws {
        let c = try Self.loadVector()
        let matrix = try XCTUnwrap(c["authorization_matrix"] as? [[String: Any]])
        var allows = 0, denies = 0
        for r in matrix {
            let granted = try XCTUnwrap(r["granted"] as? NSNumber).intValue
            let effect = try XCTUnwrap(r["effect"] as? NSNumber).intValue
            let allow = try XCTUnwrap(r["allow"] as? NSNumber).boolValue
            let g = Policy.Grant(principal: "pA", maxEffect: granted)
            if allow {
                allows += 1
                XCTAssertNoThrow(try g.authorizeObject(.signature, "pA", effect))
            } else {
                denies += 1
                XCTAssertThrowsError(try g.authorizeObject(.signature, "pA", effect)) {
                    XCTAssertEqual(($0 as? NaalpError)?.kind, "EffectNotAuthorized")
                }
            }
            XCTAssertEqual(Policy.authorizes(granted, Policy.normalizeEffect(effect)), allow)
        }
        XCTAssertTrue(allows > 0 && denies > 0, "matrix must exercise both allow and deny")
    }

    // R-6.5: only a signature-derived identity is an authorization principal; a transport/foreign/
    // client source is refused UnauthenticatedPrincipal, and even a read_only object is denied from it.
    func testOnlySignaturePrincipal() throws {
        let c = try Self.loadVector()
        let srcs = try XCTUnwrap(c["principal_sources"] as? [[String: Any]])
        let map: [String: Policy.PrincipalSource] = [
            "signature": .signature, "transport_metadata": .transportMetadata,
            "foreign_header": .foreignHeader, "client_name": .clientName,
        ]
        let g = Policy.Grant(principal: "pA", maxEffect: Policy.DESTRUCTIVE)
        for ps in srcs {
            let src = try XCTUnwrap(map[try XCTUnwrap(ps["source"] as? String)])
            let accepted = try XCTUnwrap(ps["accepted"] as? NSNumber).boolValue
            if accepted {
                XCTAssertEqual(try Policy.resolveAuthPrincipal(src, "pA"), "pA")
                XCTAssertNoThrow(try g.authorizeObject(src, "pA", Policy.READ_ONLY))
            } else {
                XCTAssertThrowsError(try Policy.resolveAuthPrincipal(src, "pA")) {
                    XCTAssertEqual(($0 as? NaalpError)?.kind, "UnauthenticatedPrincipal")
                }
                XCTAssertThrowsError(try g.authorizeObject(src, "pA", Policy.READ_ONLY)) {
                    XCTAssertEqual(($0 as? NaalpError)?.kind, "UnauthenticatedPrincipal")
                }
            }
        }
    }

    // R-6.4: safetyLabelFromExt extracts a well-formed {1:tstr,2:tstr} label, reports absence, and
    // rejects a malformed/incomplete label MalformedSafetyLabel — never silently accepting it.
    func testSafetyLabelFromExt() throws {
        let c = try Self.loadVector()
        let sl = try XCTUnwrap(c["safety_label"] as? [String: Any])
        let risk = try XCTUnwrap(sl["risk"] as? String)
        let scope = try XCTUnwrap(sl["scope"] as? String)
        let extKey = try XCTUnwrap(sl["ext_key"] as? NSNumber).uint64Value

        let ext: [(CborValue, CborValue)] = [(.u(extKey), .m([(.u(1), .t(risk)), (.u(2), .t(scope))]))]
        let (label, present) = try Policy.safetyLabelFromExt(ext)
        XCTAssertTrue(present)
        XCTAssertEqual(label?.risk, risk)
        XCTAssertEqual(label?.scope, scope)

        // absent
        let empty: [(CborValue, CborValue)] = []
        XCTAssertFalse(try Policy.safetyLabelFromExt(empty).present)

        // malformed: ext[1] present but not a map
        XCTAssertThrowsError(try Policy.safetyLabelFromExt([(.u(extKey), .u(9))])) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "MalformedSafetyLabel")
        }
        // incomplete: missing scope
        XCTAssertThrowsError(try Policy.safetyLabelFromExt([(.u(extKey), .m([(.u(1), .t("x"))]))])) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "MalformedSafetyLabel")
        }
    }
}
