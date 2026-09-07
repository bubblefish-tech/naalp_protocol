// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C21 NAALP-PAY payment-import higher-tier conformance for the Swift SDK (design.md §24; R-PAY-1..6),
// graded against the shared independent corpus vectors/payment/cases.json (NOT produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): the closed format registry + the charge effect; the
// PaymentImport and ChargeBinding body/head/content-id (including the >2^53 amount round-trip and the
// minimal import); the parse round-trip; the fail-closed wire edges (descending keys -> NonCanonical,
// currency-as-bstr look-alike -> PayMalformed, absent mandatory field -> PayMalformed); and the
// value-bearing binding guarantee expressed STRUCTURALLY — a wrong amount, wrong payee, or substituted
// foreign payload yields a DIFFERENT ChargeBinding content id (the input a §7 approval would reject as
// ApprovalMismatch).
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the PaymentImport COSE_Sign1 signature. Swift is
// PURE-ONLY for ML-DSA on the general envelope/COSE_Sign1 verification path, so the reference's ML-DSA
// import signature is demonstrated with a real Ed25519 (RFC 8032) sign/verify round-trip; and
// verifyPaymentImport correctly FLOORS a pure-Ed25519 (level-0) object under every profile
// (ProfileDowngrade), refusing to fake an ML-DSA verdict — honest F2/F4, mirroring the PHP port.
//
// AuthorizeCharge (this wave): composes the real §7 approval + single-use consume ledger (Naalp.Approval)
// landed alongside this port. All four deny paths (UnknownPaymentFormat, ApprovalMismatch, ApprovalExpired,
// ApprovalRequired) and success-consumes-exactly-once (replay -> AlreadyConsumed) are graded here against
// vectors/payment/cases.json's ap2 import + charge-binding + mismatch vectors.
//
// Written test-first: Naalp.Payment is absent until Payment.swift lands, so this fails RED with a
// compile error ("cannot find 'Payment' in scope"); a mutation putting the payee into the import body's
// foreign field flips "ap2 import body == oracle".
//
// Run:  swift test --filter PaymentTests

import Foundation
import XCTest
@testable import Naalp

final class PaymentTests: XCTestCase {

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

    static func u64(_ v: Any?) throws -> UInt64 {
        return try XCTUnwrap(v as? NSNumber, "expected a JSON number").uint64Value
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/payment/cases.json")
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
            throw XCTSkip("vectors/payment/cases.json not present (standalone build)")
        }
        return v
    }

    /// Build a PaymentImport from a corpus import dict (format/amount/currency/payee_hex/not_after/foreign_hex).
    static func imp(_ d: [String: Any]) throws -> Payment.PaymentImport {
        return Payment.PaymentImport(
            format: try u64(d["format"]),
            amount: try u64(d["amount"]),
            currency: try XCTUnwrap(d["currency"] as? String),
            payee: hexToBytes(try XCTUnwrap(d["payee_hex"] as? String)),
            notAfter: try u64(d["not_after"]),
            foreign: hexToBytes(try XCTUnwrap(d["foreign_hex"] as? String)))
    }

    // 1. the closed format registry and the charge effect equal the oracle; an unknown format is refused.
    func testFormatRegistryAndChargeEffect() throws {
        let c = try Self.loadVector()
        let vocab = try XCTUnwrap(c["format_vocabulary"] as? [[String: Any]])
        for e in vocab {
            let code = try Self.u64(e["code"])
            XCTAssertTrue(Payment.isRegisteredFormat(code), "format code \(code) registered")
            XCTAssertEqual(Payment.formatName(code), e["name"] as? String, "format name == oracle")
        }
        XCTAssertFalse(Payment.isRegisteredFormat(try Self.u64(c["unknown_format"])), "unknown format not registered")
        XCTAssertEqual(UInt64(Payment.CHARGE_EFFECT), try Self.u64(c["charge_effect"]), "charge effect == oracle")
    }

    // 2. THE LOAD-BEARING property and the mutation target: for each imported format, the PaymentImport
    //    and ChargeBinding body/head/content-id (and the foreign content-id) equal the oracle byte-for-byte.
    func testImportByteParityAgainstOracle() throws {
        let c = try Self.loadVector()
        let imports = try XCTUnwrap(c["imports"] as? [String: Any])
        for name in ["ap2", "acp", "x402"] {
            let iv = try XCTUnwrap(imports[name] as? [String: Any])
            let p = try Self.imp(iv)
            XCTAssertEqual(Self.toHex(try p.bytes()), iv["body_hex"] as? String, "\(name) import body == oracle")
            XCTAssertEqual(Self.toHex(try p.head()), iv["head_hex"] as? String, "\(name) import head == oracle")
            XCTAssertEqual(Self.toHex(try p.id()), iv["id_hex"] as? String, "\(name) import id == oracle")
            XCTAssertEqual(Self.toHex(p.foreignId()), iv["foreign_id_hex"] as? String, "\(name) foreign id == oracle")
            let cb = p.chargeBinding()
            let cbv = try XCTUnwrap(iv["charge_binding"] as? [String: Any])
            XCTAssertEqual(Self.toHex(try cb.bytes()), cbv["body_hex"] as? String, "\(name) charge-binding body == oracle")
            XCTAssertEqual(Self.toHex(try cb.head()), cbv["head_hex"] as? String, "\(name) charge-binding head == oracle")
            XCTAssertEqual(Self.toHex(try cb.contentId()), cbv["id_hex"] as? String, "\(name) charge-binding id == oracle")
        }
    }

    // 3. the >2^53 amount (0x0102030405060708) round-trips byte-exact through the import body AND the
    //    charge binding (uint64 all the way, no float64); the oracle carries it as a JSON string.
    func testBigAmountRoundTrip() throws {
        let c = try Self.loadVector()
        let ba = try XCTUnwrap(c["big_amount"] as? [String: Any])
        let amount = try XCTUnwrap(UInt64(try XCTUnwrap(ba["amount_str"] as? String)))
        XCTAssertGreaterThan(amount, UInt64(1) << 53, "oracle big amount is > 2^53")
        let p = Payment.PaymentImport(
            format: try Self.u64(ba["format"]), amount: amount,
            currency: try XCTUnwrap(ba["currency"] as? String),
            payee: Self.hexToBytes(try XCTUnwrap(ba["payee_hex"] as? String)),
            notAfter: try Self.u64(ba["not_after"]),
            foreign: Self.hexToBytes(try XCTUnwrap(ba["foreign_hex"] as? String)))
        XCTAssertEqual(Self.toHex(try p.bytes()), ba["body_hex"] as? String, "big-amount import body == oracle")
        XCTAssertEqual(Self.toHex(try p.id()), ba["id_hex"] as? String, "big-amount import id == oracle")
        let cbv = try XCTUnwrap(ba["charge_binding"] as? [String: Any])
        XCTAssertEqual(Self.toHex(try p.chargeBinding().bytes()), cbv["body_hex"] as? String, "big-amount charge-binding body == oracle")
        XCTAssertEqual(Self.toHex(try p.chargeBinding().contentId()), cbv["id_hex"] as? String, "big-amount charge-binding id == oracle")
        let recovered = try Payment.parsePaymentImport(try p.bytes())
        XCTAssertEqual(recovered.amount, amount, "amount round-trips byte-exact (>2^53 not corrupted)")
    }

    // 4. the minimal import (format 1, amount 0, empty currency/payee, not_after 0, empty foreign).
    func testMinimalImport() throws {
        let c = try Self.loadVector()
        let m = try XCTUnwrap(c["minimal"] as? [String: Any])
        let p = try Self.imp(m)
        XCTAssertEqual(Self.toHex(try p.bytes()), m["body_hex"] as? String, "minimal import body == oracle")
        XCTAssertEqual(Self.toHex(try p.id()), m["id_hex"] as? String, "minimal import id == oracle")
        XCTAssertNoThrow(try Payment.parsePaymentImport(try p.bytes()), "minimal import parses")
    }

    // 5. descending top-level keys -> the strict decoder rejects NonCanonical (the corpus verdict), and
    //    parsePaymentImport surfaces that as PayMalformed; the canonical body parses and re-encodes.
    func testKeysOutOfOrderRejected() throws {
        let c = try Self.loadVector()
        let e = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["keys_out_of_order"] as? [String: Any])
        let p = try Self.imp(e)
        XCTAssertEqual(Self.toHex(try p.bytes()), e["canonical_body_hex"] as? String, "canonical import body == oracle")
        let canon = Self.hexToBytes(try XCTUnwrap(e["canonical_body_hex"] as? String))
        let noncanon = Self.hexToBytes(try XCTUnwrap(e["noncanonical_body_hex"] as? String))
        XCTAssertNoThrow(try Cbor.decode(canon), "canonical body decodes")
        XCTAssertNoThrow(try Payment.parsePaymentImport(canon), "canonical body parses")
        XCTAssertThrowsError(try Cbor.decode(noncanon)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, e["reject"] as? String, "descending-key body rejected NonCanonical")
        }
        XCTAssertThrowsError(try Payment.parsePaymentImport(noncanon)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "PayMalformed", "parse surfaces NonCanonical as PayMalformed")
        }
    }

    // 6. an empty foreign payload is PRESENT and valid with its OWN foreign_id (distinct from a populated
    //    one), and BOTH differ from a body whose foreign field is ABSENT (rejected PayMalformed).
    func testEmptyVsAbsentForeign() throws {
        let c = try Self.loadVector()
        let base = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["keys_out_of_order"] as? [String: Any])
        let ea = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["empty_vs_absent"] as? [String: Any])
        let emptyV = try XCTUnwrap(ea["empty_foreign"] as? [String: Any])
        let popV = try XCTUnwrap(ea["populated_foreign"] as? [String: Any])

        let empty = Payment.PaymentImport(
            format: try Self.u64(base["format"]), amount: try Self.u64(base["amount"]),
            currency: try XCTUnwrap(base["currency"] as? String),
            payee: Self.hexToBytes(try XCTUnwrap(base["payee_hex"] as? String)),
            notAfter: try Self.u64(base["not_after"]), foreign: [])
        let populated = Payment.PaymentImport(
            format: try Self.u64(base["format"]), amount: try Self.u64(base["amount"]),
            currency: try XCTUnwrap(base["currency"] as? String),
            payee: Self.hexToBytes(try XCTUnwrap(base["payee_hex"] as? String)),
            notAfter: try Self.u64(base["not_after"]),
            foreign: Self.hexToBytes(try XCTUnwrap(popV["foreign_hex"] as? String)))

        XCTAssertEqual(Self.toHex(try empty.bytes()), emptyV["body_hex"] as? String, "empty-foreign body == oracle")
        XCTAssertEqual(Self.toHex(try populated.bytes()), popV["body_hex"] as? String, "populated-foreign body == oracle")
        XCTAssertEqual(Self.toHex(empty.foreignId()), emptyV["foreign_id_hex"] as? String, "empty foreign id == oracle")
        XCTAssertNotEqual(Self.toHex(empty.foreignId()), Self.toHex(populated.foreignId()), "empty vs populated foreign ids differ")
        XCTAssertNotEqual(Self.toHex(try empty.id()), Self.toHex(try populated.id()), "empty vs populated import ids differ")
        XCTAssertNoThrow(try Payment.parsePaymentImport(try empty.bytes()), "empty-foreign parses")
        XCTAssertNoThrow(try Payment.parsePaymentImport(try populated.bytes()), "populated-foreign parses")
        let absent = Self.hexToBytes(try XCTUnwrap((ea["absent_field"] as? [String: Any])?["body_hex"] as? String))
        XCTAssertThrowsError(try Payment.parsePaymentImport(absent)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "PayMalformed", "absent foreign field rejected")
        }
    }

    // 7. a look-alike with field-3 (currency) as a bstr where a tstr is required is rejected PayMalformed.
    func testLookAlikeRejected() throws {
        let c = try Self.loadVector()
        let la = try XCTUnwrap((c["edge_cases"] as? [String: Any])?["look_alike"] as? [String: Any])
        let body = Self.hexToBytes(try XCTUnwrap(la["body_hex"] as? String))
        XCTAssertThrowsError(try Payment.parsePaymentImport(body)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "PayMalformed", "look-alike (bstr currency) rejected")
        }
    }

    // 8. the value-bearing binding guarantee (STRUCTURAL): a wrong amount (+8000), a wrong payee
    //    ("merchant:evil-store"), or a substituted foreign payload each yields a DIFFERENT ChargeBinding
    //    content id — equal to the oracle's, and distinct from the honest charge id. This is exactly the
    //    input a §7 approval would fail to match (ApprovalMismatch); the ledger/consume flow is out of scope.
    func testChargeBindingMismatchIds() throws {
        let c = try Self.loadVector()
        let ap2 = try XCTUnwrap((c["imports"] as? [String: Any])?["ap2"] as? [String: Any])
        let mm = try XCTUnwrap(c["mismatch"] as? [String: Any])
        let base = try Self.imp(ap2)
        let baseChargeId = Self.toHex(try base.chargeBinding().contentId())

        let wrongAmount = Payment.PaymentImport(format: base.format, amount: base.amount + 8000,
                                                currency: base.currency, payee: base.payee,
                                                notAfter: base.notAfter, foreign: base.foreign)
        XCTAssertEqual(Self.toHex(try wrongAmount.chargeBinding().contentId()),
                       mm["wrong_amount_charge_id_hex"] as? String, "wrong-amount charge id == oracle")
        XCTAssertNotEqual(Self.toHex(try wrongAmount.chargeBinding().contentId()), baseChargeId, "wrong amount changes the charge id")

        let wrongPayee = Payment.PaymentImport(format: base.format, amount: base.amount,
                                               currency: base.currency, payee: Array("merchant:evil-store".utf8),
                                               notAfter: base.notAfter, foreign: base.foreign)
        XCTAssertEqual(Self.toHex(try wrongPayee.chargeBinding().contentId()),
                       mm["wrong_payee_charge_id_hex"] as? String, "wrong-payee charge id == oracle")
        XCTAssertNotEqual(Self.toHex(try wrongPayee.chargeBinding().contentId()), baseChargeId, "wrong payee changes the charge id")

        let substituted = Payment.PaymentImport(format: base.format, amount: base.amount,
                                                currency: base.currency, payee: base.payee, notAfter: base.notAfter,
                                                foreign: Self.hexToBytes(try XCTUnwrap(mm["substituted_foreign_hex"] as? String)))
        XCTAssertEqual(Self.toHex(substituted.foreignId()), mm["substituted_foreign_id_hex"] as? String, "substituted foreign id == oracle")
        XCTAssertEqual(Self.toHex(try substituted.chargeBinding().contentId()),
                       mm["substituted_charge_id_hex"] as? String, "substituted charge id == oracle")
        XCTAssertNotEqual(Self.toHex(try substituted.chargeBinding().contentId()), baseChargeId, "substituted payload changes the charge id")
    }

    // 9. ED25519-DEMONSTRATED (isolation, NOT corpus-graded) + honest F2/F4 profile floor: a PaymentImport
    //    signs and verifies as a COSE_Sign1 under a real Ed25519 key; a foreign key is rejected; and
    //    verifyPaymentImport correctly FLOORS the pure-Ed25519 (level-0) object (ProfileDowngrade) rather
    //    than faking an ML-DSA verdict.
    func testEd25519SignedImportDemoAndProfileFloor() throws {
        let c = try Self.loadVector()
        let ap2 = try XCTUnwrap((c["imports"] as? [String: Any])?["ap2"] as? [String: Any])
        let p = try Self.imp(ap2)
        let seed = [UInt8](repeating: 0x77, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let obj = try Payment.signPaymentImport(p, Cose.ALG_ED25519, seed)

        XCTAssertTrue(try Cose.coseVerify1(Cose.ALG_ED25519, pk, obj), "ed25519 signed import verifies")
        let foreignPk = try Cose.ed25519PublicKey([UInt8](repeating: 0x66, count: 32))
        XCTAssertFalse(try Cose.coseVerify1(Cose.ALG_ED25519, foreignPk, obj), "foreign-key signed import rejected")

        XCTAssertThrowsError(try Payment.verifyPaymentImport(obj, Cose.PROFILE_ENTERPRISE, Cose.ALG_ED25519, pk)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ProfileDowngrade",
                           "pure Ed25519 (level 0) floored under the profile — honest F2/F4, not a faked ML-DSA green")
        }
    }

    // ---- AuthorizeCharge: composes the real §7 approval + single-use consume ledger (this wave) -----
    // MUTATION TARGET: neutering the effect-coverage check (`Policy.authorizes(appr.grant, CHARGE_EFFECT)`)
    // to always pass flips testAuthorizeChargeEffectNotCoveredDenied (a read_only grant would then
    // wrongly authorize a non_idempotent_write charge).

    struct PSetup {
        let p: Payment.PaymentImport
        let chargeCID: [UInt8]
        let ledger: Approval.Ledger
        let appr: Approval.ApprovalRecord
        let verify: Approval.Verify
        let apprSig: [UInt8]
    }

    /// A real ap2 import (from the corpus), a fresh consume ledger, and a valid Ed25519-signed approval
    /// binding the import's charge-binding content id with the given granted effect.
    func makeCharge(grant: UInt64 = UInt64(Policy.NON_IDEMPOTENT_WRITE)) throws -> PSetup {
        let c = try Self.loadVector()
        let ap2 = try XCTUnwrap((c["imports"] as? [String: Any])?["ap2"] as? [String: Any])
        let p = try Self.imp(ap2)
        let chargeCID = try p.chargeBinding().contentId()

        let ledger = try Approval.Ledger.open(
            FileManager.default.temporaryDirectory.appendingPathComponent("naalp-pay-\(UUID().uuidString).wal").path)

        let seed = [UInt8](repeating: 0x51, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let approverID = try Identity.signerId(Cose.ALG_ED25519, pk)
        let appr = Approval.ApprovalRecord(approves: chargeCID, approver: approverID, grant: grant, nonce: [9, 9], notAfter: 1_000_000)
        let sig = try Approval.signApproval(appr, seed)
        let verify: Approval.Verify = { m, s in Cose.ed25519Verify(pk, m, s) }
        return PSetup(p: p, chargeCID: chargeCID, ledger: ledger, appr: appr, verify: verify, apprSig: sig)
    }

    // 10. success: the charge authorizes and consumes exactly once; a replay is AlreadyConsumed (no
    //     double-spend, the fail-closed §7 single-use guarantee).
    func testAuthorizeChargeSuccessConsumesOnce() throws {
        let s = try makeCharge()
        defer { try? s.ledger.close() }
        let entry = try Payment.authorizeCharge(s.p, s.appr, s.verify, s.apprSig, "payer:alice", 500, s.ledger)
        XCTAssertEqual(entry.approvalID, try s.appr.id(), "ledger entry names the consumed approval")
        XCTAssertTrue(s.ledger.isConsumed(try s.appr.id()), "approval consumed after authorization")

        XCTAssertThrowsError(try Payment.authorizeCharge(s.p, s.appr, s.verify, s.apprSig, "payer:alice", 500, s.ledger), "replay") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed", "spent approval is not fresh authority")
        }
        XCTAssertEqual(s.ledger.len(), 1, "exactly one ledger append across the honest call and its replay")
    }

    // 11. deny path 1: an unregistered format is UnknownPaymentFormat, fail-closed, no ledger append.
    func testAuthorizeChargeUnknownFormatDenied() throws {
        let s = try makeCharge()
        defer { try? s.ledger.close() }
        let bad = Payment.PaymentImport(format: 99, amount: s.p.amount, currency: s.p.currency,
                                        payee: s.p.payee, notAfter: s.p.notAfter, foreign: s.p.foreign)
        XCTAssertThrowsError(try Payment.authorizeCharge(bad, s.appr, s.verify, s.apprSig, "payer:alice", 500, s.ledger)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownPaymentFormat", "an unregistered format is not chargeable")
        }
        XCTAssertEqual(s.ledger.len(), 0, "no ledger append on an unknown-format charge")
    }

    // 12. deny path 2: a wrong-amount charge's binding content id (the corpus mismatch vector) no longer
    //     matches the approval -> ApprovalMismatch, fail-closed, no ledger append.
    func testAuthorizeChargeApprovalMismatchDenied() throws {
        let s = try makeCharge()
        defer { try? s.ledger.close() }
        let c = try Self.loadVector()
        let mm = try XCTUnwrap(c["mismatch"] as? [String: Any])
        let wrongAmount = Payment.PaymentImport(format: s.p.format, amount: s.p.amount + 8000, currency: s.p.currency,
                                                payee: s.p.payee, notAfter: s.p.notAfter, foreign: s.p.foreign)
        XCTAssertEqual(Self.toHex(try wrongAmount.chargeBinding().contentId()),
                       mm["wrong_amount_charge_id_hex"] as? String, "wrong-amount charge id == oracle (non-circular)")
        XCTAssertThrowsError(try Payment.authorizeCharge(wrongAmount, s.appr, s.verify, s.apprSig, "payer:alice", 500, s.ledger)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalMismatch", "wrong-amount charge id no longer matches the approval")
        }
        XCTAssertEqual(s.ledger.len(), 0, "no ledger append on a mismatched charge")
    }

    // 13. a further VerifyApproval-failure reason: an expired approval -> ApprovalExpired, no ledger append.
    func testAuthorizeChargeApprovalExpiredDenied() throws {
        let s = try makeCharge()
        defer { try? s.ledger.close() }
        XCTAssertThrowsError(try Payment.authorizeCharge(s.p, s.appr, s.verify, s.apprSig, "payer:alice", 2_000_000, s.ledger)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalExpired", "past not_after is denied")
        }
        XCTAssertEqual(s.ledger.len(), 0, "no ledger append on an expired approval")
    }

    // 14. deny path 3: the approval's granted effect (read_only) does not cover the charge's
    //     non_idempotent_write -> ApprovalRequired, no ledger append. THE MUTATION TARGET.
    func testAuthorizeChargeEffectNotCoveredDenied() throws {
        let s = try makeCharge(grant: UInt64(Policy.READ_ONLY))
        defer { try? s.ledger.close() }
        XCTAssertThrowsError(try Payment.authorizeCharge(s.p, s.appr, s.verify, s.apprSig, "payer:alice", 500, s.ledger)) {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalRequired", "a read_only grant does not cover the charge")
        }
        XCTAssertEqual(s.ledger.len(), 0, "no ledger append when the granted effect is insufficient")
    }

    // 15. deny path 4 (replay, standalone): a second authorization of the SAME approval after a first
    //     success is AlreadyConsumed with no second ledger append (single-use, no double-spend).
    func testAuthorizeChargeReplayDeniedNoDoubleSpend() throws {
        let s = try makeCharge()
        defer { try? s.ledger.close() }
        XCTAssertNoThrow(try Payment.authorizeCharge(s.p, s.appr, s.verify, s.apprSig, "payer:alice", 500, s.ledger), "first charge succeeds")
        XCTAssertThrowsError(try Payment.authorizeCharge(s.p, s.appr, s.verify, s.apprSig, "payer:bob", 500, s.ledger), "replay by a different `by`") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed", "single-use: a spent approval is not fresh authority")
        }
        XCTAssertEqual(s.ledger.len(), 1, "the replay makes no second append (no double-spend)")
    }
}
