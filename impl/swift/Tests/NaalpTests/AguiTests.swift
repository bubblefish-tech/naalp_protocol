// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 NAALP-AGUI UI-consent-binding conformance for the Swift SDK (design.md §24; R-AGUI-1..6),
// graded against the shared independent corpus vectors/agui/cases.json (NOT produced by this code):
// the receipt-chained shown-event bodies/heads/ids, the running and final chain heads, the genesis
// prev (48 zero bytes), the >2^53 seq carried byte-exact (big_seq, via a decimal string), the minimal
// and empty-vs-absent bodies, the non-canonical / malformed rejections, and the omitted-shown-event
// HOLE detected at its POSITION.
//
// CORPUS-GRADED (pure, signature-independent): all of the byte surfaces above, plus the kind
// vocabulary, the shown-chain walk, and the hole position.
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the signed shown-chain and the UI consent
// binding, which REUSES the just-landed Swift Approval §7 approval BINDING (verifyApproval) UNCHANGED
// (agui carries NO consume ledger — the consume loop is demonstrated through mcp's AuthorizeCall). Swift
// is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204 path), so the
// UI-event and approval signatures are real Ed25519 (RFC 8032) round-trips via an injected verifier
// (as Approval/Audit do): a valid consent binds the shown-and-approved action; a SUBSTITUTED action
// (different content id) is rejected ActionSubstituted; a chain with no approved event is UINoConsent;
// an expired approval is ApprovalExpired; a wrong key is BadSignature — honest F2/F4, mirroring the PHP
// port. The reference's ML-DSA cross-language signed pins are NOT reproducible here and are NOT fabricated.
//
// verifyUIEvent (this wave): the impl/go/agui.VerifyUIEvent counterpart operating on a full tagged
// COSE_Sign1 (as Payment.verifyPaymentImport does), graded in isolation — real Ed25519 sign/verify at
// the raw COSE_Sign1 layer, the honest ProfileDowngrade floor, and the UIMalformed entry check.
//
// Written test-first: Naalp.Agui is absent until Agui.swift lands, so this fails RED with a compile
// error ("cannot find 'Agui' in scope"). The load-bearing mutation removing the ActionSubstituted check
// in verifyConsent flips "substituted action -> ActionSubstituted" (the executed action is no longer
// required to be the exact one shown and approved).
//
// Run:  swift test --filter AguiTests

import Foundation
import XCTest
@testable import Naalp

final class AguiTests: XCTestCase {

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
            let p = dir.appendingPathComponent("vectors/agui/cases.json")
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
            throw XCTSkip("vectors/agui/cases.json not present (standalone build)")
        }
        return v
    }

    static func errKind(_ fn: () throws -> Void) -> String {
        do { try fn(); return "no-error" } catch let e as NaalpError { return e.kind } catch { return "\(type(of: error))" }
    }

    /// Build a UIEvent from a corpus event object (session supplied by the caller).
    static func eventOf(_ ev: [String: Any], _ session: [UInt8]) throws -> Agui.UIEvent {
        return Agui.UIEvent(session: session,
                            kind: try Self.u64(ev["kind"]),
                            action: hexToBytes(try XCTUnwrap(ev["action_hex"] as? String)),
                            seq: try Self.u64(ev["seq"]),
                            prev: hexToBytes(try XCTUnwrap(ev["prev_hex"] as? String)))
    }

    // ---- the receipt-chained shown-event bodies, running heads, and final head ---------------------

    func testChainBodiesAndHeadsMatchOracle() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))
        XCTAssertEqual(Self.toHex(Agui.genesis()), c["genesis_hex"] as? String, "genesis == 48 zero bytes")

        let chain = try XCTUnwrap(c["chain"] as? [String: Any])
        let events = try XCTUnwrap(chain["events"] as? [[String: Any]])
        var running = Agui.genesis()
        for ev in events {
            let e = try Self.eventOf(ev, session)
            XCTAssertEqual(Self.toHex(running), ev["prev_hex"] as? String, "prev links to the running head")
            XCTAssertEqual(Self.toHex(try e.bytes()), ev["body_hex"] as? String, "event body == oracle")
            XCTAssertEqual(Self.toHex(try e.head()), ev["head_hex"] as? String, "event head == oracle")
            XCTAssertEqual(Self.toHex(try e.id()), ev["id_hex"] as? String, "event id == oracle")
            running = try e.head()
        }
        XCTAssertEqual(Self.toHex(running), chain["final_head_hex"] as? String, "final chain head == oracle")
    }

    // ---- a >2^53 seq round-trips byte-exact (carried as a decimal string, never a JSON number) -----

    func testBigSeqByteExact() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))
        let bs = try XCTUnwrap(c["big_seq"] as? [String: Any])
        let seq = try XCTUnwrap(UInt64(try XCTUnwrap(bs["seq_str"] as? String)), "seq parses")
        XCTAssertGreaterThan(seq, UInt64(1) << 53, "seq exceeds 2^53")
        let e = Agui.UIEvent(session: session, kind: try Self.u64(bs["kind"]),
                             action: Self.hexToBytes(try XCTUnwrap(bs["action_hex"] as? String)),
                             seq: seq, prev: Self.hexToBytes(try XCTUnwrap(bs["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try e.bytes()), bs["body_hex"] as? String, "big-seq body == oracle")
        XCTAssertEqual(Self.toHex(try e.head()), bs["head_hex"] as? String, "big-seq head == oracle")
        XCTAssertEqual(Self.toHex(try e.id()), bs["id_hex"] as? String, "big-seq id == oracle")
    }

    // ---- minimal, empty-vs-absent, non-canonical, and look-alike edge cases ------------------------

    func testEdgeCasesMatchOracle() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))

        let min = try XCTUnwrap(c["minimal"] as? [String: Any])
        let minE = Agui.UIEvent(session: Self.hexToBytes(try XCTUnwrap(min["session_hex"] as? String)),
                                kind: try Self.u64(min["kind"]),
                                action: Self.hexToBytes(try XCTUnwrap(min["action_hex"] as? String)),
                                seq: try Self.u64(min["seq"]),
                                prev: Self.hexToBytes(try XCTUnwrap(min["prev_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try minE.bytes()), min["body_hex"] as? String, "minimal body == oracle")
        XCTAssertEqual(Self.toHex(try minE.head()), min["head_hex"] as? String, "minimal head == oracle")
        XCTAssertEqual(Self.toHex(try minE.id()), min["id_hex"] as? String, "minimal id == oracle")

        let ec = try XCTUnwrap(c["edge_cases"] as? [String: Any])
        let eva = try XCTUnwrap(ec["empty_vs_absent"] as? [String: Any])

        // an empty action bstr is PRESENT and valid, distinct by content id from a populated one.
        let emptyAction = Agui.UIEvent(session: session, kind: 0, action: [], seq: 0, prev: Agui.genesis())
        XCTAssertEqual(Self.toHex(try emptyAction.id()),
                       (eva["empty_action"] as? [String: Any])?["id_hex"] as? String, "empty-action id == oracle")
        let popV = try XCTUnwrap(eva["populated_action"] as? [String: Any])
        let populated = Agui.UIEvent(session: session, kind: 0,
                                     action: Self.hexToBytes(try XCTUnwrap(popV["action_hex"] as? String)),
                                     seq: 0, prev: Agui.genesis())
        XCTAssertEqual(Self.toHex(try populated.id()), popV["id_hex"] as? String, "populated-action id == oracle")
        XCTAssertNotEqual(try emptyAction.id(), try populated.id(), "empty != populated by id")

        // a body whose mandatory field 3 (action) is ABSENT is rejected UIMalformed.
        let absent = try XCTUnwrap(eva["absent_field"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Agui.parseUIEvent(Self.hexToBytes(try XCTUnwrap(absent["body_hex"] as? String))) },
                       absent["reject"] as? String, "absent action field rejected")

        // a ui-event-shaped body lacking its field-5 back-pointer (prev) is rejected UIMalformed.
        let la = try XCTUnwrap(ec["look_alike"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Agui.parseUIEvent(Self.hexToBytes(try XCTUnwrap(la["body_hex"] as? String))) },
                       la["reject"] as? String, "look-alike (missing prev) rejected")

        // keys emitted descending -> the strict decoder rejects, surfaced as UIMalformed by the parser.
        let koo = try XCTUnwrap(ec["keys_out_of_order"] as? [String: Any])
        XCTAssertEqual(Self.errKind { _ = try Agui.parseUIEvent(Self.hexToBytes(try XCTUnwrap(koo["noncanonical_body_hex"] as? String))) },
                       "UIMalformed", "non-canonical body rejected UIMalformed")
        XCTAssertNoThrow(try Agui.parseUIEvent(Self.hexToBytes(try XCTUnwrap(koo["canonical_body_hex"] as? String))), "canonical body parses")
    }

    // ---- an unknown kind is rejected; a walked chain enforces contiguity ---------------------------

    func testKindVocabularyAndWalk() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))
        for k in try XCTUnwrap(c["kind_vocabulary"] as? [[String: Any]]) {
            XCTAssertTrue(Agui.isKnownKind(try Self.u64(k["code"])), "known kind \(k["name"] ?? "?")")
        }
        XCTAssertFalse(Agui.isKnownKind(try Self.u64(c["unknown_kind"])), "unknown kind not known")

        let events = try XCTUnwrap((c["chain"] as? [String: Any])?["events"] as? [[String: Any]])
        let full = try events.map { try Self.eventOf($0, session) }
        let shown = try Agui.walkShown(full)
        XCTAssertEqual(shown.count, full.count, "walked chain preserves all events")
        XCTAssertEqual(Self.toHex(shown[shown.count - 1].head),
                       (c["chain"] as? [String: Any])?["final_head_hex"] as? String, "walked final head == oracle")
    }

    // ---- an omitted shown-event is a detectable HOLE at its POSITION -------------------------------

    func testHoleDetectedAtPosition() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))
        let events = try XCTUnwrap((c["chain"] as? [String: Any])?["events"] as? [[String: Any]])

        // the gappy chain: present ev0 and ev2, the middle shown-event (ev1) omitted.
        let gappy = [try Self.eventOf(events[0], session), try Self.eventOf(events[2], session)]
        let (pos, hole) = try Agui.detectHole(gappy)
        XCTAssertTrue(hole, "omitted shown-event detected as a hole")
        XCTAssertEqual(pos, try XCTUnwrap(((c["hole"] as? [String: Any])?["position"] as? NSNumber)?.intValue), "hole position == oracle")

        // the contiguous full chain has no hole.
        let full = try events.map { try Self.eventOf($0, session) }
        let (_, fullHole) = try Agui.detectHole(full)
        XCTAssertFalse(fullHole, "the contiguous chain has no hole")

        // walkShown rejects the gappy chain (fail-closed) — the same broken link.
        XCTAssertEqual(Self.errKind { _ = try Agui.walkShown(gappy) }, "UIChainBroken", "walkShown rejects the gappy chain")
    }

    // ---- the signed shown-chain + the UI consent binding (Ed25519, isolation) ----------------------
    // MUTATION TARGET: removing the ActionSubstituted check in verifyConsent makes a substituted action
    // (a different content id) pass, flipping "substituted action -> ActionSubstituted".

    func testConsentBindsExactShownAction() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))
        let actionCid = Self.hexToBytes(try XCTUnwrap(c["action_cid_hex"] as? String))
        let actionBytes = Self.hexToBytes(try XCTUnwrap(c["action_bytes_hex"] as? String))
        let substituted = Self.hexToBytes(try XCTUnwrap(c["substituted_bytes_hex"] as? String))

        // non-circular: the action content ids come from the corpus, recomputed here from the bytes.
        XCTAssertEqual(Self.toHex(Agui.contentId(actionBytes)), c["action_cid_hex"] as? String, "action content id == oracle")
        XCTAssertEqual(Self.toHex(Agui.contentId(substituted)), c["substituted_cid_hex"] as? String, "substituted content id == oracle")

        // the UI authority signs the shown chain (shown, args-shown, approved).
        let uiSeed = [UInt8](repeating: 0x29, count: 32)
        let uiPk = try Cose.ed25519PublicKey(uiSeed)
        let uiVerify: Agui.Verify = { m, s in Cose.ed25519Verify(uiPk, m, s) }
        let events = try XCTUnwrap((c["chain"] as? [String: Any])?["events"] as? [[String: Any]])
        var chain: [Agui.UIEvent] = []
        var sigs: [[UInt8]] = []
        for ev in events {
            let e = try Self.eventOf(ev, session)
            chain.append(e)
            sigs.append(try Agui.signUIEvent(e, uiSeed))
        }
        let verified = try Agui.verifyShownChain(chain, sigs, uiVerify)
        XCTAssertEqual(verified.count, chain.count, "signed shown chain verifies")

        // the human approval binds the shown-and-approved action content id (grant non_idempotent_write).
        let humanSeed = [UInt8](repeating: 0x2b, count: 32)
        let humanPk = try Cose.ed25519PublicKey(humanSeed)
        let humanID = try Identity.signerId(Cose.ALG_ED25519, humanPk)
        let appr = Approval.ApprovalRecord(approves: actionCid, approver: humanID,
                                           grant: UInt64(Policy.NON_IDEMPOTENT_WRITE), nonce: [5, 5], notAfter: 1000)
        let apprSig = try Approval.signApproval(appr, humanSeed)
        let humanVerify: Approval.Verify = { m, s in Cose.ed25519Verify(humanPk, m, s) }

        // honest consent: the executed action IS the shown-and-approved one -> authorized.
        XCTAssertNoThrow(try Agui.verifyConsent(chain, actionBytes, appr, humanVerify, apprSig, 500), "honest consent authorized")

        // a SUBSTITUTED action (different content id) is rejected.
        XCTAssertThrowsError(try Agui.verifyConsent(chain, substituted, appr, humanVerify, apprSig, 500), "substituted action") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ActionSubstituted", "substituted action -> ActionSubstituted")
        }

        // a chain with no approved event has no consent to bind.
        XCTAssertThrowsError(try Agui.verifyConsent([chain[0]], actionBytes, appr, humanVerify, apprSig, 500), "no approved event") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UINoConsent", "no approved event -> UINoConsent")
        }

        // an expired approval is rejected (the §7 approval expiry, reused unchanged).
        XCTAssertThrowsError(try Agui.verifyConsent(chain, actionBytes, appr, humanVerify, apprSig, 1001), "expired") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalExpired", "expired approval -> ApprovalExpired")
        }

        // an approval verified under the WRONG key is BadSignature (fail-closed).
        let foreignPk = try Cose.ed25519PublicKey([UInt8](repeating: 0x58, count: 32))
        let foreignVerify: Approval.Verify = { m, s in Cose.ed25519Verify(foreignPk, m, s) }
        XCTAssertThrowsError(try Agui.verifyConsent(chain, actionBytes, appr, foreignVerify, apprSig, 500), "wrong key") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature", "wrong key -> BadSignature")
        }
    }

    // ---- verifyUIEvent: full COSE_Sign1 verification under the profile (isolation, mirrors Payment) --
    // MUTATION TARGET: removing the `level < Cose.profileMinLevel(profile)` floor check in verifyUIEvent
    // flips "pure Ed25519 floored under every profile" — the signed object would then verify and return
    // the event instead of throwing ProfileDowngrade.

    func testVerifyUIEventSignedRoundTripAndProfileFloor() throws {
        let c = try Self.loadVector()
        let session = Self.hexToBytes(try XCTUnwrap(c["session_hex"] as? String))
        let events = try XCTUnwrap((c["chain"] as? [String: Any])?["events"] as? [[String: Any]])
        let e = try Self.eventOf(events[0], session)

        let seed = [UInt8](repeating: 0x77, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let obj = try Agui.signUIEventObject(e, Cose.ALG_ED25519, seed)

        // real Ed25519 sign/verify round-trip at the raw COSE_Sign1 layer (isolation), and a foreign key
        // is rejected -- mirrors Payment.testEd25519SignedImportDemoAndProfileFloor's pattern exactly.
        XCTAssertTrue(try Cose.coseVerify1(Cose.ALG_ED25519, pk, obj), "ed25519 signed ui-event verifies")
        let foreignPk = try Cose.ed25519PublicKey([UInt8](repeating: 0x88, count: 32))
        XCTAssertFalse(try Cose.coseVerify1(Cose.ALG_ED25519, foreignPk, obj), "foreign-key signed ui-event rejected")

        // verifyUIEvent correctly FLOORS the pure-Ed25519 (level-0) object under every profile --
        // honest F2/F4, mirroring Payment.verifyPaymentImport (never a faked ML-DSA green).
        XCTAssertThrowsError(try Agui.verifyUIEvent(obj, Cose.PROFILE_ENTERPRISE, Cose.ALG_ED25519, pk)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ProfileDowngrade",
                           "pure Ed25519 (level 0) floored under the profile — honest F2/F4, not a faked ML-DSA green")
        }
        XCTAssertThrowsError(try Agui.verifyUIEvent(obj, Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ProfileDowngrade", "floored under every registered profile, not just Enterprise")
        }

        // an object shaped like a UI event but not a tagged COSE_Sign1 (the bare body bytes) is rejected
        // UIMalformed -- verifyUIEvent's fail-closed entry check.
        XCTAssertThrowsError(try Agui.verifyUIEvent(try e.bytes(), Cose.PROFILE_PUBLIC, Cose.ALG_ED25519, pk)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UIMalformed", "a bare body (not a tagged COSE_Sign1) is rejected")
        }
    }
}
