// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C6 approval + the durable single-use consume ledger higher-tier conformance for the Swift SDK
// (design.md §7; R-7.1..7.4), graded against the shared independent corpus vectors/approval/cases.json
// (values from the corpus, NEVER produced by this code).
//
// CORPUS-GRADED (pure, signature-independent): the approval body bytes + content id (the ledger key)
// for approvals A and B; the durable hash-chained consume ledger — the genesis head, each accepted
// entry's byte-exact body + head_after + seq, the AlreadyConsumed replay, and the final chain head;
// and the broken-link LedgerCorrupt rejection.
//
// ED25519-DEMONSTRATED (isolation, NOT corpus-graded): the approval and held-result SIGNATURES. Swift
// is PURE-ONLY for ML-DSA (SwiftDilithium 3.6.0 has no deterministic-from-seed FIPS 204 path), so the
// reference's ML-DSA approval signature is demonstrated with a real Ed25519 (RFC 8032) sign/verify
// round-trip through the injected verifier; a wrong-args content id is ApprovalMismatch, an expired
// approval is ApprovalExpired, and a tampered signature is BadSignature — honest F2/F4, mirroring the
// PHP port. The reference's ML-DSA cross-language signed pins are NOT reproducible here and are NOT
// fabricated.
//
// ATOMICITY (concrete concurrent race, real threads): §7.2 requires the single-use compare-and-set be
// atomic. Swift/Linux has real threads, so testExactlyOnceUnderRace releases N threads together on ONE
// approval id and asserts exactly one wins, the rest get AlreadyConsumed, and the durable ledger
// records exactly one entry — the compare-and-set has no read-then-write TOCTOU.
//
// DEFERRED (documented, honest F2/F4): the §7.5 ledger-signed ConsumeReceipt / ConsumeFork / ReceiptSet
// layer is graded by the separate vectors/consume_receipt corpus and is NOT part of this wave; the core
// §7.2 single-use replay IS ported and graded here.
//
// Written test-first: Naalp.Approval is absent until Approval.swift lands, so this fails RED with a
// compile error ("cannot find 'Approval' in scope"). The load-bearing mutation removing the
// compare-and-set guard flips "exactly one thread wins the single-use consume (atomic CAS)".
//
// Run:  swift test --filter ApprovalTests

import Dispatch
import Foundation
import XCTest
@testable import Naalp

final class ApprovalTests: XCTestCase {

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
            let p = dir.appendingPathComponent("vectors/approval/cases.json")
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
            throw XCTSkip("vectors/approval/cases.json not present (standalone build)")
        }
        return v
    }

    static func approval(_ c: [String: Any], _ name: String) throws -> Approval.ApprovalRecord {
        let arr = try XCTUnwrap(c["approvals"] as? [[String: Any]])
        let d = try XCTUnwrap(arr.first { ($0["name"] as? String) == name }, "approval \(name)")
        return Approval.ApprovalRecord(
            approves: hexToBytes(try XCTUnwrap(d["approves_hex"] as? String)),
            approver: try XCTUnwrap(d["approver"] as? String),
            grant: try u64(d["grant"]),
            nonce: hexToBytes(try XCTUnwrap(d["nonce_hex"] as? String)),
            notAfter: try u64(d["not_after"]))
    }

    static func tempLedgerPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("naalp-approval-\(UUID().uuidString).wal").path
    }

    // 1. the approval body bytes and the approval content id (the ledger key) equal the oracle.
    func testApprovalBytesMatchOracle() throws {
        let c = try Self.loadVector()
        let arr = try XCTUnwrap(c["approvals"] as? [[String: Any]])
        XCTAssertFalse(arr.isEmpty, "corpus has approvals")
        for d in arr {
            let name = try XCTUnwrap(d["name"] as? String)
            let rec = try Self.approval(c, name)
            XCTAssertEqual(Self.toHex(try rec.bytes()), d["record_hex"] as? String, "\(name) record bytes == oracle")
            XCTAssertEqual(Self.toHex(try rec.id()), d["approval_id_hex"] as? String, "\(name) approval id == oracle")
        }
    }

    // 2. the durable consume ledger reproduces the oracle scenario byte-for-byte: genesis head, each
    //    accepted entry's body + seq + head_after, the AlreadyConsumed replay, and the final head.
    func testLedgerScenarioMatchesOracle() throws {
        let c = try Self.loadVector()
        let led = try XCTUnwrap(c["ledger"] as? [String: Any])
        let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
        defer { try? ledger.close() }
        XCTAssertEqual(Self.toHex(ledger.head()), led["genesis_head_hex"] as? String, "genesis head == oracle")

        let consumes = try XCTUnwrap(led["consumes"] as? [[String: Any]])
        for (i, cons) in consumes.enumerated() {
            let id = Self.hexToBytes(try XCTUnwrap(cons["approval_id_hex"] as? String))
            let by = try XCTUnwrap(cons["by"] as? String)
            let expect = try XCTUnwrap(cons["expect"] as? String)
            switch expect {
            case "ok":
                let e = try ledger.consume(id, by)
                XCTAssertEqual(e.seq, try Self.u64(cons["seq"]), "consume \(i) seq == oracle")
                XCTAssertEqual(Self.toHex(try e.bytes()), cons["entry_hex"] as? String, "consume \(i) entry == oracle")
                XCTAssertEqual(Self.toHex(ledger.head()), cons["head_after_hex"] as? String, "consume \(i) head_after == oracle")
            case "AlreadyConsumed":
                XCTAssertThrowsError(try ledger.consume(id, by), "consume \(i) is a replay") {
                    XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed", "replay rejected AlreadyConsumed")
                }
            default:
                XCTFail("unknown expect \(expect)")
            }
        }
        XCTAssertEqual(Self.toHex(ledger.head()), led["final_head_hex"] as? String, "final head == oracle")
        XCTAssertEqual(ledger.len(), 2, "two distinct approvals consumed")
    }

    // 3. durability across close/reopen (persist-before-ack, R-7.2): a returned consume survives, the
    //    reopened ledger rebuilds the same head, and it still rejects a re-consume.
    func testDurabilityAcrossReopen() throws {
        let c = try Self.loadVector()
        let idA = Self.hexToBytes(try XCTUnwrap((try XCTUnwrap(c["approvals"] as? [[String: Any]]))[0]["approval_id_hex"] as? String))
        let path = Self.tempLedgerPath()

        let l1 = try Approval.Ledger.open(path)
        _ = try l1.consume(idA, "c1")
        let headBefore = Self.toHex(l1.head())
        try l1.close() // simulates process exit after the fsync'd consume

        let l2 = try Approval.Ledger.open(path)
        defer { try? l2.close() }
        XCTAssertTrue(l2.isConsumed(idA), "consume survives reopen")
        XCTAssertEqual(Self.toHex(l2.head()), headBefore, "head rebuilt from the WAL")
        XCTAssertThrowsError(try l2.consume(idA, "c2"), "re-consume after reopen") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed", "reopened ledger rejects a replay")
        }
    }

    // 4. THE ATOMICITY RACE PROOF and the load-bearing mutation target: N threads released together on
    //    ONE approval id — exactly one wins, the rest get AlreadyConsumed, and the durable ledger records
    //    exactly one entry. Removing the compare-and-set guard flips "exactly one thread wins".
    func testExactlyOnceUnderRace() throws {
        let c = try Self.loadVector()
        let idA = Self.hexToBytes(try XCTUnwrap((try XCTUnwrap(c["approvals"] as? [[String: Any]]))[0]["approval_id_hex"] as? String))
        let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
        defer { try? ledger.close() }

        let N = 64
        let cond = NSCondition()
        var go = false
        let counter = NSLock()
        var wins = 0, alreadys = 0, others = 0
        let group = DispatchGroup()

        for _ in 0..<N {
            group.enter()
            let t = Thread {
                defer { group.leave() }
                cond.lock(); while !go { cond.wait() }; cond.unlock() // released together (max contention)
                do {
                    _ = try ledger.consume(idA, "consumer")
                    counter.lock(); wins += 1; counter.unlock()
                } catch let e as NaalpError where e.kind == "AlreadyConsumed" {
                    counter.lock(); alreadys += 1; counter.unlock()
                } catch {
                    counter.lock(); others += 1; counter.unlock()
                }
            }
            t.stackSize = 1 << 20
            t.start()
        }
        Thread.sleep(forTimeInterval: 0.05) // let the threads reach the wait
        cond.lock(); go = true; cond.broadcast(); cond.unlock()
        group.wait()

        XCTAssertEqual(others, 0, "no unexpected errors under the race")
        XCTAssertEqual(wins, 1, "exactly one thread wins the single-use consume (atomic CAS)")
        XCTAssertEqual(alreadys, N - 1, "the other N-1 threads get AlreadyConsumed")
        XCTAssertEqual(ledger.len(), 1, "the durable ledger recorded exactly one consume")
    }

    // 5. Ed25519-DEMONSTRATED verify (isolation): a correct approval verifies; a mutated-args content id
    //    is ApprovalMismatch; an expired approval is ApprovalExpired; a tampered signature is BadSignature.
    func testApprovalVerifyEd25519Demo() throws {
        let c = try Self.loadVector()
        let rec = try Self.approval(c, "A")
        let argsID = Self.hexToBytes(try XCTUnwrap((c["args"] as? [String: Any])?["content_id_hex"] as? String))
        let expiry = try XCTUnwrap(c["expiry"] as? [String: Any])
        let validAt = try Self.u64(expiry["valid_at"])
        let expiredAt = try Self.u64(expiry["expired_at"])
        let wrong = Self.hexToBytes(try XCTUnwrap((c["mismatch"] as? [String: Any])?["wrong_args_id_hex"] as? String))

        let seed = [UInt8](repeating: 0x0b, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let sig = try Approval.signApproval(rec, seed)
        let verify: Approval.Verify = { msg, s in Cose.ed25519Verify(pk, msg, s) }

        XCTAssertNoThrow(try Approval.verifyApproval(rec, verify, sig, argsID, validAt), "valid approval verifies at not_after")
        XCTAssertThrowsError(try Approval.verifyApproval(rec, verify, sig, wrong, validAt), "wrong args") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalMismatch", "mutated args -> ApprovalMismatch")
        }
        XCTAssertThrowsError(try Approval.verifyApproval(rec, verify, sig, argsID, expiredAt), "expired") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalExpired", "past not_after -> ApprovalExpired")
        }
        var bad = sig; bad[bad.count - 1] ^= 0x01
        XCTAssertThrowsError(try Approval.verifyApproval(rec, verify, bad, argsID, validAt), "tampered sig") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "BadSignature", "tampered signature -> BadSignature")
        }
    }

    // 6. the held outcome (§7.4) is a distinct, signed, attributable result — not a silent success/denial.
    func testHeldResultSignedEd25519Demo() throws {
        let c = try Self.loadVector()
        let approves = Self.hexToBytes(try XCTUnwrap((c["args"] as? [String: Any])?["content_id_hex"] as? String))
        let h = Approval.HeldResult(approves: approves, reason: "awaiting approver")
        let seed = [UInt8](repeating: 0x0c, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let sig = try Approval.signHeld(h, seed)
        XCTAssertTrue(Cose.ed25519Verify(pk, try h.bytes(), sig), "held-result signature verifies")
        var bad = sig; bad[0] ^= 0x01
        XCTAssertFalse(Cose.ed25519Verify(pk, try h.bytes(), bad), "tampered held-result signature rejected")
    }

    // 7. the hash-chain mutation test: a WAL whose second entry's prev != SHA-384(entry0) is rejected on
    //    open (LedgerCorrupt). A replay that ignored `prev` would accept it.
    func testLedgerCorruptDetected() throws {
        let c = try Self.loadVector()
        let arr = try XCTUnwrap(c["approvals"] as? [[String: Any]])
        let idA = Self.hexToBytes(try XCTUnwrap(arr[0]["approval_id_hex"] as? String))
        let idB = Self.hexToBytes(try XCTUnwrap(arr[1]["approval_id_hex"] as? String))
        let genesis = [UInt8](repeating: 0, count: Approval.HEAD_SIZE)

        let e0 = Approval.LedgerEntry(seq: 0, prev: genesis, approvalID: idA, by: "c1")
        // e1's prev is left at genesis instead of SHA-384(e0) — a broken link.
        let e1bad = Approval.LedgerEntry(seq: 1, prev: genesis, approvalID: idB, by: "c1")

        func framed(_ rec: [UInt8]) -> [UInt8] {
            let n = UInt32(rec.count)
            return [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] + rec
        }
        let path = Self.tempLedgerPath()
        let blob = Data(framed(try e0.bytes()) + framed(try e1bad.bytes()))
        try blob.write(to: URL(fileURLWithPath: path))

        XCTAssertThrowsError(try Approval.Ledger.open(path), "corrupt WAL") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "LedgerCorrupt", "broken-link WAL rejected LedgerCorrupt")
        }
    }

    // 8. consumeApproval (T20.1, the draft "## Approval state machine" composed choke point): exercises
    //    every reaction and the two precedence rules (mismatch over every cell; expiry over
    //    AlreadyConsumed), plus the effect-ceiling / grant-range / bad-signature refusals, and asserts
    //    the ledger length so a mutant that returns the right Kind but still appends is caught. Mirrors
    //    Go's TestConsumeApprovalPrecedence / Rust's consume_approval_precedence.
    func testConsumeApprovalPrecedence() throws {
        let seed = [UInt8](repeating: 0x07, count: 32)
        let pk = try Cose.ed25519PublicKey(seed)
        let verify: Approval.Verify = { msg, s in Cose.ed25519Verify(pk, msg, s) }
        let argsCid = Array("args-content-id-A".utf8)
        let wrongCid = Array("args-content-id-B".utf8)

        func mk(_ grant: UInt64, _ notAfter: UInt64) throws -> (Approval.ApprovalRecord, [UInt8]) {
            let a = Approval.ApprovalRecord(approves: argsCid, approver: "approver-1", grant: grant,
                                            nonce: [0x01, 0x02], notAfter: notAfter)
            return (a, try Approval.signApproval(a, seed))
        }
        func kind(_ e: Error) -> String? { (e as? NaalpError)?.kind }

        // approved + consume -> consumed (len 1); a second consume -> AlreadyConsumed (len stays 1).
        do {
            let (a, sig) = try mk(UInt64(Policy.DESTRUCTIVE), 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            _ = try Approval.consumeApproval(a, verify, sig, argsCid, 500, Policy.READ_ONLY, ledger, "by")
            XCTAssertEqual(ledger.len(), 1)
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, argsCid, 500, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "AlreadyConsumed")
            }
            XCTAssertEqual(ledger.len(), 1)
        }
        // expired + consume -> ApprovalExpired; nothing appended.
        do {
            let (a, sig) = try mk(UInt64(Policy.DESTRUCTIVE), 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, argsCid, 2000, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "ApprovalExpired")
            }
            XCTAssertEqual(ledger.len(), 0)
        }
        // expiry over consume: success, then a second past not_after -> ApprovalExpired (never
        // AlreadyConsumed), ledger untouched (len stays 1).
        do {
            let (a, sig) = try mk(UInt64(Policy.DESTRUCTIVE), 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            _ = try Approval.consumeApproval(a, verify, sig, argsCid, 500, Policy.READ_ONLY, ledger, "by")
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, argsCid, 2000, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "ApprovalExpired")
            }
            XCTAssertEqual(ledger.len(), 1)
        }
        // mismatch over every cell (fresh, and over an also-expired approval); no append.
        do {
            let (a, sig) = try mk(UInt64(Policy.DESTRUCTIVE), 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, wrongCid, 500, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "ApprovalMismatch")
            }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, wrongCid, 2000, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "ApprovalMismatch") // mismatch before expiry
            }
            XCTAssertEqual(ledger.len(), 0)
        }
        // a rejected mismatch leaves the ledger clean, so a later valid consume still succeeds.
        do {
            let (a, sig) = try mk(UInt64(Policy.DESTRUCTIVE), 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, wrongCid, 500, Policy.READ_ONLY, ledger, "by"))
            XCTAssertEqual(ledger.len(), 0)
            _ = try Approval.consumeApproval(a, verify, sig, argsCid, 500, Policy.READ_ONLY, ledger, "by")
            XCTAssertEqual(ledger.len(), 1)
        }
        // effect ceiling (THE MUTATION-WITNESS TARGET, T20.1 step 5): granted effect below the action's
        // required effect -> ApprovalRequired, no append.
        do {
            let (a, sig) = try mk(UInt64(Policy.READ_ONLY), 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, argsCid, 500, Policy.DESTRUCTIVE, ledger, "by")) {
                XCTAssertEqual(kind($0), "ApprovalRequired", "insufficient grant must be refused ApprovalRequired")
            }
            XCTAssertEqual(ledger.len(), 0)
        }
        // grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing.
        do {
            let (a, sig) = try mk(7, 1000)
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, sig, argsCid, 500, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "ApprovalRequired")
            }
            XCTAssertEqual(ledger.len(), 0)
        }
        // bad signature (checked first) -> BadSignature.
        do {
            let (a, sig) = try mk(UInt64(Policy.DESTRUCTIVE), 1000)
            var bad = sig; bad[bad.count - 1] ^= 0x01
            let ledger = try Approval.Ledger.open(Self.tempLedgerPath())
            defer { try? ledger.close() }
            XCTAssertThrowsError(try Approval.consumeApproval(a, verify, bad, argsCid, 500, Policy.READ_ONLY, ledger, "by")) {
                XCTAssertEqual(kind($0), "BadSignature")
            }
            XCTAssertEqual(ledger.len(), 0)
        }
    }
}
