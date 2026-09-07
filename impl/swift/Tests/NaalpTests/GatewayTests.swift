// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 gateway-decision conformance for the Swift SDK (design.md §24; R-GW-1..6), graded against the
// shared independent corpus vectors/gateway/cases.json (NOT produced by this code). A
// GatewayDecision {1:decision,2:action,3:policy,4:effect} is a signed decision an enforcement
// gateway of any vendor emits as portable evidence: its authority is the signature over the bytes,
// so it verifies offline and re-verifies IDENTICALLY when served by a party other than the gateway.
//
// CORPUS-GRADED (pure): the deterministic body/head/content-id byte-for-byte for allow/deny/hold,
// the closed decision set, the strict-decoder rejections (non-canonical / absent field / sibling
// look-alike), the empty-vs-absent policy distinction, the minimal decision, and the fail-closed
// effect class.
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the signature binding + third-party
// re-serve. Swift is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS
// 204 path), so the gateway signature is demonstrated with a real Ed25519 (RFC 8032) round-trip via
// swift-crypto. The reference profile floor is level 3 (ML-DSA), so a pure-Ed25519 object is
// correctly REJECTED by verifyDecision (ProfileDowngrade) — that rejection, plus UnknownAlg, is the
// verifyDecision behavior reachable on the pure port; its success path needs an ML-DSA signature.
//
// Written test-first: Naalp.Gateway is absent until Gateway.swift lands, so this fails RED with a
// compile error; forcing the decision field to a constant flips "deny body == oracle".
//
// Run:  swift test --filter GatewayTests

import XCTest
@testable import Naalp

final class GatewayTests: XCTestCase {

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

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/gateway/cases.json")
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
            throw XCTSkip("vectors/gateway/cases.json not present (standalone build)")
        }
        return v
    }

    /// Build a GatewayDecision from a corpus decision object.
    static func decFrom(_ dv: [String: Any]) throws -> GatewayDecision {
        let decision = UInt64(try XCTUnwrap(dv["decision"] as? Int))
        let action = hexToBytes(try XCTUnwrap(dv["action_hex"] as? String))
        let policy = hexToBytes(try XCTUnwrap(dv["policy_hex"] as? String))
        let effect = UInt64(try XCTUnwrap(dv["effect"] as? Int))
        return GatewayDecision(decision: decision, action: action, policy: policy, effect: effect)
    }

    /// Catch a NaalpError and return its kind (or "no-error"), for rejection assertions.
    static func errKind(_ fn: () throws -> Void) -> String {
        do { try fn(); return "no-error" } catch let e as NaalpError { return e.kind } catch { return "\(type(of: error))" }
    }

    // 1. body/head/content-id byte-parity vs the non-circular oracle, for every decision. A mutation
    //    to any bytes() field flips a *_hex assertion.
    func testDecisionBytesHeadIdMatchOracle() throws {
        let c = try Self.loadVector()
        let decisions = try XCTUnwrap(c["decisions"] as? [String: Any])
        for name in ["allow", "deny", "hold"] {
            let dv = try XCTUnwrap(decisions[name] as? [String: Any])
            let d = try Self.decFrom(dv)
            XCTAssertEqual(Self.toHex(try d.bytes()), dv["body_hex"] as? String, "\(name) body == oracle")
            XCTAssertEqual(Self.toHex(try d.head()), dv["head_hex"] as? String, "\(name) head (SHA-384) == oracle")
            XCTAssertEqual(Self.toHex(try d.id()), dv["id_hex"] as? String, "\(name) content-id == oracle")
        }
    }

    // 2. the closed decision vocabulary; an out-of-set code is not known.
    func testClosedDecisionVocabulary() throws {
        let c = try Self.loadVector()
        let vocab = try XCTUnwrap(c["decision_vocabulary"] as? [[String: Any]])
        for e in vocab {
            let code = UInt64(try XCTUnwrap(e["code"] as? Int))
            let name = try XCTUnwrap(e["name"] as? String)
            XCTAssertTrue(Gateway.isKnownDecision(code), "known: \(name)")
            XCTAssertEqual(Gateway.decisionName(code), name, "name of code \(code)")
        }
        let unknown = UInt64(try XCTUnwrap(c["unknown_decision"] as? Int))
        XCTAssertFalse(Gateway.isKnownDecision(unknown), "unknown decision not known")
        XCTAssertEqual(Gateway.decisionName(unknown), "unknown", "unknown decision name")
    }

    // 3. edge case: top-level keys DESCENDING (4,3,2,1) are rejected NonCanonical by the strict
    //    decoder; the canonical body parses.
    func testKeysOutOfOrderStrictDecoder() throws {
        let c = try Self.loadVector()
        let e = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["keys_out_of_order"] as? [String: Any])
        let dko = GatewayDecision(decision: UInt64(try XCTUnwrap(e["decision"] as? Int)),
                                  action: Self.hexToBytes(try XCTUnwrap(e["action_hex"] as? String)),
                                  policy: Self.hexToBytes(try XCTUnwrap(e["policy_hex"] as? String)),
                                  effect: UInt64(try XCTUnwrap(e["effect"] as? Int)))
        XCTAssertEqual(Self.toHex(try dko.bytes()), e["canonical_body_hex"] as? String,
                       "keys_out_of_order canonical body")
        let canonical = Self.hexToBytes(try XCTUnwrap(e["canonical_body_hex"] as? String))
        XCTAssertNoThrow(try Gateway.parseDecision(canonical), "canonical body parses")
        let noncanonical = Self.hexToBytes(try XCTUnwrap(e["noncanonical_body_hex"] as? String))
        XCTAssertEqual(Self.errKind { _ = try Cbor.decode(noncanonical) }, "NonCanonical",
                       "noncanonical decode rejected")
        XCTAssertEqual(Self.errKind { _ = try Gateway.parseDecision(noncanonical) }, "GwMalformed",
                       "noncanonical parse rejected")
    }

    // 4. edge case: an empty policy identity is present and valid and DISTINCT by content-id from a
    //    populated one; a body whose policy field is ABSENT is rejected (field 3 mandatory).
    func testEmptyVsAbsentPolicy() throws {
        let c = try Self.loadVector()
        let actionCid = Self.hexToBytes(try XCTUnwrap(c["action_cid_hex"] as? String))
        let ea = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["empty_vs_absent"] as? [String: Any])
        let emptyV = try XCTUnwrap(ea["empty_policy"] as? [String: Any])
        let popV = try XCTUnwrap(ea["populated_policy"] as? [String: Any])
        let empty = GatewayDecision(decision: Gateway.DECISION_ALLOW, action: actionCid, policy: [], effect: 1)
        let populated = GatewayDecision(decision: Gateway.DECISION_ALLOW, action: actionCid,
                                        policy: Self.hexToBytes(try XCTUnwrap(popV["policy_hex"] as? String)),
                                        effect: 1)
        XCTAssertEqual(Self.toHex(try empty.bytes()), emptyV["body_hex"] as? String, "empty-policy body == oracle")
        XCTAssertEqual(Self.toHex(try populated.bytes()), popV["body_hex"] as? String, "populated-policy body == oracle")
        XCTAssertNotEqual(try empty.id(), try populated.id(), "empty != populated by id")
        XCTAssertEqual(Self.toHex(try empty.id()), emptyV["id_hex"] as? String, "empty-policy id == oracle")
        let absent = try XCTUnwrap(ea["absent_field"] as? [String: Any])
        let absentBody = Self.hexToBytes(try XCTUnwrap(absent["body_hex"] as? String))
        XCTAssertEqual(Self.errKind { _ = try Gateway.parseDecision(absentBody) }, "GwMalformed",
                       "absent policy field rejected")
    }

    // 5. edge case: the smallest valid decision encodes to the oracle bytes, has a stable id, and
    //    round-trips through parseDecision.
    func testMinimalDecision() throws {
        let c = try Self.loadVector()
        let m = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["minimal"] as? [String: Any])
        let dm = GatewayDecision(decision: UInt64(try XCTUnwrap(m["decision"] as? Int)),
                                 action: Self.hexToBytes(try XCTUnwrap(m["action_hex"] as? String)),
                                 policy: Self.hexToBytes(try XCTUnwrap(m["policy_hex"] as? String)),
                                 effect: UInt64(try XCTUnwrap(m["effect"] as? Int)))
        XCTAssertEqual(Self.toHex(try dm.bytes()), m["body_hex"] as? String, "minimal body == oracle")
        XCTAssertEqual(Self.toHex(try dm.id()), m["id_hex"] as? String, "minimal id == oracle")
        let parsed = try Gateway.parseDecision(try dm.bytes())
        XCTAssertEqual(parsed.decision, UInt64(try XCTUnwrap(m["decision"] as? Int)), "minimal round-trip decision")
        XCTAssertEqual(parsed.effect, UInt64(try XCTUnwrap(m["effect"] as? Int)), "minimal round-trip effect")
    }

    // 6. edge case: a sibling C21 body (ui-event {1:bstr,...}) whose field 1 is a bstr where the
    //    decision uint is required is rejected GwMalformed.
    func testLookAlikeRejected() throws {
        let c = try Self.loadVector()
        let la = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["look_alike"] as? [String: Any])
        let body = Self.hexToBytes(try XCTUnwrap(la["body_hex"] as? String))
        XCTAssertEqual(Self.errKind { _ = try Gateway.parseDecision(body) }, "GwMalformed", "look-alike rejected")
    }

    // 7. the effect class is normalized fail-closed: an unrecognized value is destructive (R-6.2).
    func testEffectClassFailClosed() throws {
        let dfc = GatewayDecision(decision: Gateway.DECISION_DENY, action: [], policy: [], effect: 99)
        XCTAssertEqual(dfc.effectClass(), Policy.DESTRUCTIVE, "effect fail-closed to destructive")
    }

    // 8. ED25519-DEMONSTRATED (isolation): a gateway signs a decision; the raw signature verifies,
    //    and re-serving the IDENTICAL bytes verifies IDENTICALLY (third-party re-serve — authority
    //    is the signature over the bytes, not the connection). A tampered signature and a foreign key
    //    both fail.
    func testEd25519SignVerifyAndThirdPartyReserve() throws {
        let c = try Self.loadVector()
        let decisions = try XCTUnwrap(c["decisions"] as? [String: Any])
        let dsig = try Self.decFrom(try XCTUnwrap(decisions["deny"] as? [String: Any]))
        let gwSeed = [UInt8](repeating: 0x51, count: 32)
        let foreignSeed = [UInt8](repeating: 0x52, count: 32)
        let gwPk = try Cose.ed25519PublicKey(gwSeed)
        let foreignPk = try Cose.ed25519PublicKey(foreignSeed)

        let obj = try Gateway.signDecision(dsig, Cose.ALG_ED25519, gwSeed)
        let (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        let tbs = try Cose.toBeSignedRaw(prot, payload)

        // served by the gateway, then re-served by a third party: SAME bytes, no server identity, so
        // the verification result and the resolved decision are identical.
        let byGateway = Cose.ed25519Verify(gwPk, tbs, sig)
        let byThirdParty = Cose.ed25519Verify(gwPk, tbs, sig)
        XCTAssertTrue(byGateway, "gateway serves: signature verifies")
        XCTAssertTrue(byGateway == byThirdParty && byThirdParty, "third-party re-serve verifies identically")

        let reserved = try Gateway.parseDecision(payload)
        XCTAssertEqual(reserved.decision, Gateway.DECISION_DENY, "re-served resolved decision == deny")
        XCTAssertEqual(Self.toHex(reserved.action), c["action_cid_hex"] as? String,
                       "re-served action == oracle content-id")

        var tsig = sig
        tsig[tsig.count - 1] ^= 0x01
        XCTAssertFalse(Cose.ed25519Verify(gwPk, tbs, tsig), "tampered signature rejected")
        XCTAssertFalse(Cose.ed25519Verify(foreignPk, tbs, sig), "foreign key rejected")
    }

    // 9. verifyDecision real branches reachable on the pure port: a level-0 Ed25519 object is below
    //    the PROFILE_PUBLIC floor (ProfileDowngrade); an unregistered alg is UnknownAlg. (The success
    //    path needs an ML-DSA level-3 signature the pure Swift port cannot produce.)
    func testVerifyDecisionReachableBranches() throws {
        let c = try Self.loadVector()
        let decisions = try XCTUnwrap(c["decisions"] as? [String: Any])
        let dsig = try Self.decFrom(try XCTUnwrap(decisions["deny"] as? [String: Any]))
        let gwSeed = [UInt8](repeating: 0x51, count: 32)
        let gwPk = try Cose.ed25519PublicKey(gwSeed)

        let obj = try Gateway.signDecision(dsig, Cose.ALG_ED25519, gwSeed)
        XCTAssertEqual(
            Self.errKind { _ = try Gateway.verifyDecision(obj, Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, gwPk) },
            "ProfileDowngrade", "verifyDecision floors Ed25519 (ProfileDowngrade)")

        let bogus = try Gateway.signDecision(dsig, -99, gwSeed)  // header carries an unregistered alg -99
        XCTAssertEqual(
            Self.errKind { _ = try Gateway.verifyDecision(bogus, Cose.PROFILE_PUBLIC, -99, gwPk) },
            "UnknownAlg", "verifyDecision rejects unregistered alg (UnknownAlg)")
    }

    // 10. an unknown decision code is rejected by the closed-set check that verifyDecision enforces.
    func testClosedSetRejectsUnknownCode() throws {
        let c = try Self.loadVector()
        let unknown = UInt64(try XCTUnwrap(c["unknown_decision"] as? Int))
        let badDec = GatewayDecision(decision: unknown,
                                     action: Self.hexToBytes(try XCTUnwrap(c["action_cid_hex"] as? String)),
                                     policy: Self.hexToBytes(try XCTUnwrap(c["policy_hex"] as? String)),
                                     effect: 0)
        XCTAssertFalse(Gateway.isKnownDecision(badDec.decision), "closed-set rejects unknown code")
    }

    // ---- R1 (ordering, field 5) + R8 (foreign-profile, field 6) conformance, graded against the
    // optional_fields{} block of the SAME vectors/gateway/cases.json corpus. ------------------------

    // 11. field 5 present (single-boundary), field 6 present (foreign-profile), and both together:
    //     byte-parity vs the oracle, parse round-trip, and validate() raises nothing.
    func testGatewayOptionalFieldsRoundTrip() throws {
        let c = try Self.loadVector()
        let of = try XCTUnwrap(c["optional_fields"] as? [String: Any])
        let actionCid = Self.hexToBytes(try XCTUnwrap(c["action_cid_hex"] as? String))
        let policy = Self.hexToBytes(try XCTUnwrap(c["policy_hex"] as? String))

        // with_ordering: field 5 present, field 6 absent.
        let wo = try XCTUnwrap(of["with_ordering"] as? [String: Any])
        let woOrd = try XCTUnwrap(wo["ordering"] as? [String: Any])
        let dOrdering = GatewayDecision(
            decision: UInt64(try XCTUnwrap(wo["decision"] as? Int)), action: actionCid, policy: policy,
            effect: UInt64(try XCTUnwrap(wo["effect"] as? Int)),
            ordering: OrderingDisclosure(basis: UInt64(try XCTUnwrap(woOrd["basis"] as? Int)),
                                         boundary: Self.hexToBytes(try XCTUnwrap(woOrd["boundary_hex"] as? String))))
        XCTAssertEqual(Self.toHex(try dOrdering.bytes()), wo["body_hex"] as? String, "with_ordering body == oracle")
        XCTAssertEqual(Self.toHex(try dOrdering.head()), wo["head_hex"] as? String, "with_ordering head == oracle")
        XCTAssertEqual(Self.toHex(try dOrdering.id()), wo["id_hex"] as? String, "with_ordering id == oracle")
        let parsedOrdering = try Gateway.parseDecision(try dOrdering.bytes())
        XCTAssertNotNil(parsedOrdering.ordering, "with_ordering: field 5 parsed")
        XCTAssertNil(parsedOrdering.foreignProfile, "with_ordering: field 6 absent")
        XCTAssertNoThrow(try parsedOrdering.ordering!.validate(), "with_ordering validates")

        // with_foreign_profile: field 6 present, field 5 absent.
        let wf = try XCTUnwrap(of["with_foreign_profile"] as? [String: Any])
        let wfFp = try XCTUnwrap(wf["foreign_profile"] as? [String: Any])
        let dForeign = GatewayDecision(
            decision: UInt64(try XCTUnwrap(wf["decision"] as? Int)), action: actionCid, policy: policy,
            effect: UInt64(try XCTUnwrap(wf["effect"] as? Int)),
            foreignProfile: ForeignProfilePin(id: try XCTUnwrap(wfFp["id"] as? String),
                                              revision: try XCTUnwrap(wfFp["revision"] as? String)))
        XCTAssertEqual(Self.toHex(try dForeign.bytes()), wf["body_hex"] as? String, "with_foreign_profile body == oracle")
        let parsedForeign = try Gateway.parseDecision(try dForeign.bytes())
        XCTAssertNil(parsedForeign.ordering, "with_foreign_profile: field 5 absent")
        XCTAssertNotNil(parsedForeign.foreignProfile, "with_foreign_profile: field 6 parsed")
        XCTAssertEqual(parsedForeign.foreignProfile!.id, wfFp["id"] as? String)
        XCTAssertEqual(parsedForeign.foreignProfile!.revision, wfFp["revision"] as? String)
        XCTAssertNoThrow(try parsedForeign.foreignProfile!.validate(), "with_foreign_profile validates")

        // with_both: field 5 (external-mechanism, with relation) AND field 6 both present.
        let wb = try XCTUnwrap(of["with_both"] as? [String: Any])
        let wbOrd = try XCTUnwrap(wb["ordering"] as? [String: Any])
        let wbFp = try XCTUnwrap(wb["foreign_profile"] as? [String: Any])
        let dBoth = GatewayDecision(
            decision: UInt64(try XCTUnwrap(wb["decision"] as? Int)), action: actionCid, policy: policy,
            effect: UInt64(try XCTUnwrap(wb["effect"] as? Int)),
            ordering: OrderingDisclosure(basis: UInt64(try XCTUnwrap(wbOrd["basis"] as? Int)),
                                         mechanism: Self.hexToBytes(try XCTUnwrap(wbOrd["mechanism_hex"] as? String)),
                                         relation: Self.hexToBytes(try XCTUnwrap(wbOrd["relation_hex"] as? String))),
            foreignProfile: ForeignProfilePin(id: try XCTUnwrap(wbFp["id"] as? String),
                                              revision: try XCTUnwrap(wbFp["revision"] as? String)))
        XCTAssertEqual(Self.toHex(try dBoth.bytes()), wb["body_hex"] as? String, "with_both body == oracle")
        let parsedBoth = try Gateway.parseDecision(try dBoth.bytes())
        XCTAssertNotNil(parsedBoth.ordering)
        XCTAssertNotNil(parsedBoth.foreignProfile)
        XCTAssertNoThrow(try parsedBoth.ordering!.validate())
        XCTAssertNoThrow(try parsedBoth.foreignProfile!.validate())
    }

    // 12. a field-6 map omitting mandatory key 2 (revision) decodes structurally fine but fails
    //     validate() (ForeignProfileMalformed).
    func testGatewayForeignProfileMalformedRejected() throws {
        let c = try Self.loadVector()
        let of = try XCTUnwrap(c["optional_fields"] as? [String: Any])
        let e = try XCTUnwrap(of["foreign_profile_malformed"] as? [String: Any])
        let body = Self.hexToBytes(try XCTUnwrap(e["body_hex"] as? String))
        let parsed = try Gateway.parseDecision(body)
        XCTAssertNotNil(parsed.foreignProfile)
        var caught: NaalpError?
        do { try parsed.foreignProfile!.validate() } catch let err as NaalpError { caught = err }
        XCTAssertEqual(caught?.kind, e["reject"] as? String, "foreign_profile_malformed rejected")
    }

    // 13. a field-5 map violating the basis-conditioned rule decodes structurally fine but fails
    //     validate() (OrderingDisclosureMalformed).
    func testGatewayOrderingMalformedRejected() throws {
        let c = try Self.loadVector()
        let of = try XCTUnwrap(c["optional_fields"] as? [String: Any])
        let e = try XCTUnwrap(of["ordering_malformed"] as? [String: Any])
        let body = Self.hexToBytes(try XCTUnwrap(e["body_hex"] as? String))
        let parsed = try Gateway.parseDecision(body)
        XCTAssertNotNil(parsed.ordering)
        var caught: NaalpError?
        do { try parsed.ordering!.validate() } catch let err as NaalpError { caught = err }
        XCTAssertEqual(caught?.kind, e["reject"] as? String, "ordering_malformed rejected")
    }

    // 14. direct unit test of ForeignProfilePin.validate() (no oracle vector needed): missing/empty
    //     id or revision is rejected; both present and non-empty passes.
    func testForeignProfilePinValidate() throws {
        XCTAssertNoThrow(try ForeignProfilePin(id: "https://example.test/p", revision: "1").validate())
        for pin in [ForeignProfilePin(id: "", revision: "1"),
                    ForeignProfilePin(id: "https://example.test/p", revision: ""),
                    ForeignProfilePin(id: "", revision: "")] {
            XCTAssertEqual(Self.errKind { try pin.validate() }, "ForeignProfileMalformed")
        }
    }

    // 15. a field-6 map carrying a THIRD key (3) beyond the closed {1,2} set decodes structurally
    //     (the extra key does not fail decode) but fails validate() (ForeignProfileMalformed).
    func testGatewayForeignProfileExtraKeyRejected() throws {
        let c = try Self.loadVector()
        let actionCid = Self.hexToBytes(try XCTUnwrap(c["action_cid_hex"] as? String))
        let policyBytes = Self.hexToBytes(try XCTUnwrap(c["policy_hex"] as? String))
        let fp: CborValue = .m([
            (.u(1), .t("https://example-registry.test/profiles/acme")),
            (.u(2), .t("2026-01")),
            (.u(3), .t("unexpected")),
        ])
        let m: CborValue = .m([
            (.u(1), .u(Gateway.DECISION_ALLOW)),
            (.u(2), .b(actionCid)),
            (.u(3), .b(policyBytes)),
            (.u(4), .u(1)),
            (.u(6), fp),
        ])
        let body = try Cbor.encode(m)
        let parsed = try Gateway.parseDecision(body)
        XCTAssertNotNil(parsed.foreignProfile)
        XCTAssertEqual(parsed.foreignProfile!.id, "https://example-registry.test/profiles/acme")
        XCTAssertEqual(parsed.foreignProfile!.revision, "2026-01")
        XCTAssertEqual(Self.errKind { try parsed.foreignProfile!.validate() }, "ForeignProfileMalformed")
    }
}
