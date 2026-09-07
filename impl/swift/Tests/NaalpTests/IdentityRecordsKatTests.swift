// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Non-circular known-answer test for the eleven §5.2/§5.3/§5.4/R-1.4 RECORD + THREAD surfaces
// (design.md), graded against the committed independent oracle (vectors/identity_records/cases.json,
// produced by tools/identity_records_oracle.py; NOT recomputed by the SDK — F3): RevocationRecord,
// RevokedAt, VerifyRevocation, ForeignLinkRecord, VerifyForeignLink, RotationEvidence, Thread,
// Thread.attributable, ResolveThread. Every candidate/old/new key in this corpus signs with ML-DSA-65
// (alg -49), graded via the real deterministic ML-DSA verify path (MlDsa.verify, #142) — this test
// therefore exercises real cryptographic verification, not a stub.
//
// VerifyRevocation is SECURITY-CRITICAL and fail-closed (§5.3/§5.5): a revocation is valid only if
// signed by the revoked key itself OR by a deployer-configured recovery key (membership checked
// BEFORE the signature). "recovery_key_not_configured_reject" is the fail-closed anchor: a valid
// recovery-key signature with an EMPTY authorized set MUST reject SignerMismatch.
//
// Run:  swift test --package-path impl/swift --filter IdentityRecordsKatTests

import Foundation
import XCTest
@testable import Naalp

final class IdentityRecordsKatTests: XCTestCase {

    // ---- vector loading (mirrors IdentityKatTests.findVector) ---------------------------------

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

    static func bytesToHex<S: Sequence>(_ b: S) -> String where S.Element == UInt8 {
        b.map { String(format: "%02x", $0) }.joined()
    }

    static func findVector() -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent("vectors/identity_records/cases.json")
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    // ---- small JSON accessors (JSONSerialization returns loosely-typed Any) -------------------

    private func str(_ d: [String: Any], _ k: String) -> String { d[k] as? String ?? "" }
    private func u64(_ d: [String: Any], _ k: String) -> UInt64 { (d[k] as? NSNumber)?.uint64Value ?? 0 }
    private func optU64(_ d: [String: Any], _ k: String) -> UInt64? { (d[k] as? NSNumber)?.uint64Value }
    private func optStr(_ d: [String: Any], _ k: String) -> String? { d[k] as? String }
    private func intv(_ d: [String: Any], _ k: String) -> Int { (d[k] as? NSNumber)?.intValue ?? 0 }
    private func boolv(_ d: [String: Any], _ k: String) -> Bool { d[k] as? Bool ?? false }
    private func dict(_ d: [String: Any], _ k: String) -> [String: Any] { d[k] as? [String: Any] ?? [:] }
    private func optDict(_ d: [String: Any], _ k: String) -> [String: Any]? { d[k] as? [String: Any] }
    private func arr(_ d: [String: Any], _ k: String) -> [[String: Any]] { d[k] as? [[String: Any]] ?? [] }
    private func strArr(_ d: [String: Any], _ k: String) -> [String] { d[k] as? [String] ?? [] }

    private func vec() throws -> [String: Any] {
        guard let v = Self.findVector() else {
            throw XCTSkip("committed identity_records vector not present (standalone build)")
        }
        return v
    }

    // ---- RevocationRecord.bytes (§5.3) ---------------------------------------------------------

    func testRevocationRecordBytesMatchesOracle() throws {
        let c = try vec()
        let revocation = dict(c, "revocation")
        let cases = arr(revocation, "record_bytes")
        XCTAssertFalse(cases.isEmpty, "no revocation record_bytes cases")
        for tc in cases {
            let name = str(tc, "name")
            let r = Identity.RevocationRecord(key: str(tc, "key"), notAfter: u64(tc, "not_after"))
            let got = Self.bytesToHex(try r.bytes())
            XCTAssertEqual(got, str(tc, "bytes_hex"), "RevocationRecord.bytes() (\(name))")
        }
    }

    // ---- RevokedAt (§5.3) — MUTATION ANCHOR: "at_boundary_still_valid" pins `>` vs `>=` --------

    func testRevokedAtMatchesOracle() throws {
        let c = try vec()
        let revocation = dict(c, "revocation")
        let scenarios = arr(revocation, "revoked_at")
        XCTAssertFalse(scenarios.isEmpty, "no revoked_at scenarios")
        for sc in scenarios {
            let name = str(sc, "name")
            let queryKey = str(sc, "query_key")
            let queryPosition = u64(sc, "query_position")
            var revoked = false
            var notAfter: UInt64 = 0
            for rv in arr(sc, "revocations") {
                let key = str(rv, "key")
                if key != queryKey { continue }
                let na = u64(rv, "not_after")
                let rec = Identity.RevocationRecord(key: key, notAfter: na)
                if Identity.revokedAt(rec, queryPosition) {
                    revoked = true
                    notAfter = na
                }
            }
            XCTAssertEqual(revoked, boolv(sc, "expect_revoked"), name)
            if boolv(sc, "expect_revoked") {
                if let want = optU64(sc, "expect_not_after") {
                    XCTAssertEqual(notAfter, want, name)
                } else {
                    XCTFail("\(name): missing expect_not_after")
                }
            }
        }
    }

    // ---- VerifyRevocation (§5.3, §5.5) — SECURITY-CRITICAL, fail-closed ------------------------
    //
    // MUTATION ANCHORS: "recovery_key_not_configured_reject" (a valid recovery-key signature with
    // an EMPTY authorized set -> SignerMismatch) and "wrong_key_reject" — dropping the membership
    // guard flips both to accept.

    func testVerifyRevocationMatchesOracle() throws {
        let c = try vec()
        let revocation = dict(c, "revocation")
        let cases = arr(revocation, "verify")
        XCTAssertGreaterThanOrEqual(cases.count, 7, "expected all seven authorization x signature cases")
        for tc in cases {
            let name = str(tc, "name")
            let note = str(tc, "note")
            let alg = intv(tc, "candidate_alg")
            let pub = Self.hexToBytes(str(tc, "candidate_pubkey_hex"))
            let sig = Self.hexToBytes(str(tc, "sig_hex"))
            let record = dict(tc, "record")
            let rec = Identity.RevocationRecord(key: str(record, "key"), notAfter: u64(record, "not_after"))
            let recoveryIDs = strArr(tc, "authorized_recovery_ids")
            let expectValid = boolv(tc, "expect_valid")
            let expectKind = optStr(tc, "expect_error_kind") ?? ""
            do {
                try Identity.verifyRevocation(rec, alg, pub, sig, recoveryIDs)
                XCTAssertTrue(expectValid, "\(name): expected reject, got accept — \(note)")
            } catch let e as NaalpError {
                XCTAssertFalse(expectValid, "\(name): expected valid, got \(e.kind) — \(note)")
                if !expectKind.isEmpty {
                    XCTAssertEqual(e.kind, expectKind, name)
                }
            }
        }
    }

    // ---- ForeignLinkRecord.bytes (§5.4) — MUTATION ANCHOR: collapsing NFC/NFD to the same bytes
    // would flip the not-equal assertion below. ---------------------------------------------------

    func testForeignLinkRecordBytesMatchesOracle() throws {
        let c = try vec()
        let fl = dict(c, "foreign_link")
        let cases = arr(fl, "record_bytes")
        XCTAssertGreaterThanOrEqual(cases.count, 2, "expected >=2 foreign_link record_bytes cases")
        var seen: [String: String] = [:]
        for tc in cases {
            let name = str(tc, "name")
            let r = Identity.ForeignLinkRecord(controls: str(tc, "controls"),
                                               foreignID: str(tc, "foreign_id"),
                                               notAfter: u64(tc, "not_after"))
            let got = Self.bytesToHex(try r.bytes())
            XCTAssertEqual(got, str(tc, "bytes_hex"), "ForeignLinkRecord.bytes() (\(name))")
            seen[name] = got
        }
        XCTAssertNotEqual(seen["nfc_form"], seen["nfd_form_different_bytes"],
                          "NFC and NFD foreign_id forms must encode to different bytes")
    }

    // ---- VerifyForeignLink (§5.4, §5.5) ---------------------------------------------------------

    func testVerifyForeignLinkMatchesOracle() throws {
        let c = try vec()
        let fl = dict(c, "foreign_link")
        let cases = arr(fl, "verify")
        XCTAssertFalse(cases.isEmpty, "no foreign_link verify cases")
        for tc in cases {
            let name = str(tc, "name")
            let note = str(tc, "note")
            let alg = intv(tc, "candidate_alg")
            let pub = Self.hexToBytes(str(tc, "candidate_pubkey_hex"))
            let sig = Self.hexToBytes(str(tc, "sig_hex"))
            let record = dict(tc, "record")
            let rec = Identity.ForeignLinkRecord(controls: str(record, "controls"),
                                                 foreignID: str(record, "foreign_id"),
                                                 notAfter: u64(record, "not_after"))
            let now = u64(tc, "now")
            let expectKind = optStr(tc, "expect_error_kind") ?? ""
            do {
                let linked = try Identity.verifyForeignLink(rec, alg, pub, sig, now)
                XCTAssertTrue(expectKind.isEmpty, "\(name): expected error kind \(expectKind), got linked=\(linked)")
                XCTAssertEqual(linked, boolv(tc, "expect_linked"), "\(name): \(note)")
                if boolv(tc, "expect_linked") {
                    XCTAssertEqual(rec.controls, optStr(tc, "expect_controls") ?? "", name)
                    XCTAssertEqual(rec.foreignID, optStr(tc, "expect_foreign_id") ?? "", name)
                }
            } catch let e as NaalpError {
                XCTAssertFalse(expectKind.isEmpty, "\(name): unexpected error \(e.kind) — \(note)")
                XCTAssertEqual(e.kind, expectKind, name)
            }
        }
    }

    // ---- RotationEvidence / Thread / ResolveThread (§5.2, R-1.4) --------------------------------

    /// Rebuilds each RotationRecord from its logical fields (never trusted directly from
    /// record_bytes_hex) and cross-checks RotationRecord.bytes() against the oracle's
    /// record_bytes_hex, so a constant/field-ignoring encoder would diverge before resolveThread
    /// is ever reached.
    private func buildEvidence(_ evs: [[String: Any]]) throws -> [Identity.RotationEvidence] {
        var out: [Identity.RotationEvidence] = []
        for e in evs {
            let rec = Identity.RotationRecord(old: str(e, "old"), new: str(e, "new"),
                                              notBefore: u64(e, "not_before"))
            let got = Self.bytesToHex(try rec.bytes())
            XCTAssertEqual(got, str(e, "record_bytes_hex"), "RotationRecord.bytes() (RotationEvidence input)")
            out.append(Identity.RotationEvidence(
                record: rec,
                oldAlg: intv(e, "old_alg"), oldPub: Self.hexToBytes(str(e, "old_pubkey_hex")),
                oldSig: Self.hexToBytes(str(e, "old_sig_hex")),
                newAlg: intv(e, "new_alg"), newPub: Self.hexToBytes(str(e, "new_pubkey_hex")),
                newSig: Self.hexToBytes(str(e, "new_sig_hex"))
            ))
        }
        return out
    }

    /// MUTATION ANCHORS: "broken_link_old_mismatch" pins the CONTIGUITY guard and
    /// "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE guard — isolating one
    /// from the other.
    func testResolveThreadMatchesOracle() throws {
        let c = try vec()
        let thread = dict(c, "thread")
        let cases = arr(thread, "resolve")
        XCTAssertFalse(cases.isEmpty, "no thread resolve cases")
        for tc in cases {
            let name = str(tc, "name")
            let note = str(tc, "note")
            let evs = try buildEvidence(arr(tc, "evidence"))
            let expectError = optStr(tc, "expect_error") ?? ""
            do {
                let th = try Identity.resolveThread(evs)
                XCTAssertTrue(expectError.isEmpty,
                              "\(name): expected error \(expectError), got accept (root=\(th.root)) — \(note)")
                guard let want = optDict(tc, "expect_thread") else {
                    XCTFail("\(name): oracle declared no expected thread but impl accepted"); continue
                }
                XCTAssertEqual(th.root, str(want, "root"), name)
                XCTAssertEqual(th.current, str(want, "current"), name)
                XCTAssertEqual(th.chain, strArr(want, "chain"), name)
            } catch let e as NaalpError {
                XCTAssertFalse(expectError.isEmpty, "\(name): unexpected error \(e.kind) — \(note)")
                XCTAssertEqual(e.kind, expectError, name)
            }
        }
    }

    /// MUTATION ANCHOR: "unrelated_key_not_attributable" — an always-true stub flips it.
    func testThreadAttributableMatchesOracle() throws {
        let c = try vec()
        let thread = dict(c, "thread")
        let cases = arr(thread, "attributable")
        XCTAssertFalse(cases.isEmpty, "no thread attributable cases")
        for tc in cases {
            let name = str(tc, "name")
            let tj = dict(tc, "thread")
            let th = Identity.Thread(root: str(tj, "root"), current: str(tj, "current"), chain: strArr(tj, "chain"))
            let query = str(tc, "query")
            XCTAssertEqual(th.attributable(query), boolv(tc, "expect"), "\(name): attributable(\(query))")
        }
    }
}
