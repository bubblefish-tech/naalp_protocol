// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Non-circular known-answer test for the STEP-2 approval-cluster additions (task #174): the T1.5
// ledger-signed ConsumeReceipt / ConsumeForkEvidence / ReceiptSet layer (design.md §7.5,
// NAALP-REQ-121, graded against vectors/consume_receipt/cases.json) and the R-TDCS-5 audience /
// R-TDCS-3 refusal surfaces (design.md §25, graded against vectors/trust_decision/cases.json), plus
// the R-TDCS-4 freshness-independence composite (verifyFreshIndependent, synthetic scenario — the Go
// reference's tdcs_test.go is not vector-graded either). Values come from the committed independent
// oracles, NEVER recomputed by this code (F3).
//
// CRYPTO: the consume-receipt layer signs/verifies with REAL deterministic ML-DSA-65 (MlDsa.swift, the
// CNaalpMldsa BoringSSL shim, #142) — this is genuine cryptographic verification, matching how
// IdentityRecordsKatTests already exercises MlDsa.verify. The approval side of
// verifyFreshIndependent reuses the existing Ed25519 demonstration (Approval.signApproval /
// Approval.verifyApproval, unchanged) since verifyFreshIndependent takes an INDEPENDENTLY injected
// verifier per side.
//
// Port extra (task #174 launch note): `Approval.Ledger.openLedger` is the reference-named unsigned
// factory added alongside the pre-existing `open` (which already served the unsigned case) and the
// new `openLedgerSigned` (which binds a real signing key so `consumeWithReceipt` can mint ledger-signed
// receipts).
//
// Run:  swift test --package-path impl/swift --filter ApprovalKat

import Dispatch
import Foundation
import XCTest
@testable import Naalp

final class ApprovalKatTests: XCTestCase {

    // ---- vector loading (mirrors IdentityRecordsKatTests/ApprovalTests) ------------------------

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

    static func findVector(_ relPath: String) -> [String: Any]? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let p = dir.appendingPathComponent(relPath)
            if FileManager.default.fileExists(atPath: p.path),
               let data = try? Data(contentsOf: p),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    static func tempLedgerPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("naalp-approval-kat-\(UUID().uuidString).wal").path
    }

    // ---- small JSON accessors (JSONSerialization returns loosely-typed Any) -------------------

    private func str(_ d: [String: Any], _ k: String) -> String { d[k] as? String ?? "" }
    // R12 (NAALP-01-03): a 64-bit position/counter above 2^53 is carried as a decimal string so a
    // float64 decoder cannot round it; accept a JSON number OR a decimal string and parse it exactly.
    private func u64(_ d: [String: Any], _ k: String) -> UInt64 {
        if let n = d[k] as? NSNumber { return n.uint64Value }
        if let s = d[k] as? String, let v = UInt64(s) { return v }
        return 0
    }
    private func dict(_ d: [String: Any], _ k: String) -> [String: Any] { d[k] as? [String: Any] ?? [:] }
    private func arr(_ d: [String: Any], _ k: String) -> [[String: Any]] { d[k] as? [[String: Any]] ?? [] }

    private func crVec() throws -> [String: Any] {
        guard let v = Self.findVector("vectors/consume_receipt/cases.json") else {
            throw XCTSkip("committed consume_receipt vector not present (standalone build)")
        }
        return v
    }

    private func tdVec() throws -> [String: Any] {
        guard let v = Self.findVector("vectors/trust_decision/cases.json") else {
            throw XCTSkip("committed trust_decision vector not present (standalone build)")
        }
        return v
    }

    // ---- ML-DSA-65 keypair helper (real crypto, #142) --------------------------------------------

    private func ledgerKeypair(_ seedByte: UInt8) throws -> (pk: [UInt8], sign: Approval.Signer, verify: Approval.Verify) {
        let seed = [UInt8](repeating: seedByte, count: 32)
        let pk = try MlDsa.keygenFromSeed(seed, MlDsa.ALG_MLDSA65)
        let sign: Approval.Signer = { msg in try MlDsa.sign(seed, msg, MlDsa.ALG_MLDSA65) }
        let verify: Approval.Verify = { msg, sig in (try? MlDsa.verify(pk, msg, sig, MlDsa.ALG_MLDSA65)) ?? false }
        return (pk, sign, verify)
    }

    private func receiptFromJSON(_ rj: [String: Any]) -> Approval.ConsumeReceipt {
        Approval.ConsumeReceipt(
            ledger: Self.hexToBytes(str(rj, "ledger_hex")),
            approvalID: Self.hexToBytes(str(rj, "approval_id_hex")),
            position: u64(rj, "position"))
    }

    // ================================================================================================
    // T1.5: ConsumeReceipt byte parity, sign/verify, fork detection, CAS, race, wire cases
    // ================================================================================================

    // 1. every consume-receipt body is byte-identical to the independent oracle (Go == Rust == Swift).
    func testConsumeReceiptBytesMatchOracle() throws {
        let c = try crVec()
        var all = [dict(c, "base")]
        all.append(contentsOf: arr(c, "sequence"))
        for f in arr(c, "forks") {
            all.append(dict(f, "a"))
            all.append(dict(f, "b"))
        }
        XCTAssertFalse(all.isEmpty, "no consume-receipt cases")
        for rj in all {
            let got = Self.toHex(try receiptFromJSON(rj).bytes())
            XCTAssertEqual(got, str(rj, "body_hex"), "receipt body mismatch")
        }
    }

    // 2. a ledger-signed receipt verifies under the ledger key (REQ-121, REAL ML-DSA-65); an unnamed
    //    ledger, a tampered signature, and the wrong ledger key are each rejected fail-closed.
    func testConsumeReceiptSignVerify() throws {
        let c = try crVec()
        let (_, sign, verify) = try ledgerKeypair(0x51)
        let r = receiptFromJSON(dict(c, "base"))

        let sig = try Approval.signConsumeReceipt(r, sign)
        XCTAssertNoThrow(try Approval.verifyConsumeReceipt(r, verify, sig), "valid ledger-signed receipt rejected")

        // unnamed ordering authority (empty ledger id) is not evidence.
        let unnamed = Approval.ConsumeReceipt(ledger: [], approvalID: r.approvalID, position: r.position)
        XCTAssertThrowsError(try Approval.verifyConsumeReceipt(unnamed, verify, sig), "unnamed-ledger receipt accepted") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ConsumeReceiptUnsigned", "unnamed ledger")
        }

        // tampered signature.
        var bad = sig; bad[bad.count - 1] ^= 0x01
        XCTAssertThrowsError(try Approval.verifyConsumeReceipt(r, verify, bad), "tampered signature accepted") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ConsumeReceiptUnsigned", "tampered sig")
        }

        // wrong ledger key.
        let (_, _, otherVerify) = try ledgerKeypair(0x52)
        XCTAssertThrowsError(try Approval.verifyConsumeReceipt(r, otherVerify, sig), "wrong ledger key accepted") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ConsumeReceiptUnsigned", "wrong key")
        }
    }

    // 3. (case a) two ledger-signed receipts for the SAME approval id with DIFFERENT positions are
    //    detected as a fork, and the surfaced evidence carries BOTH positions and verifies as a
    //    non-repudiable double-spend proof. A byte-identical re-emission is a benign duplicate.
    func testConsumeForkDetected() throws {
        let c = try crVec()
        guard let fk = arr(c, "forks").first(where: { str($0, "name") == "same_ledger_diff_position" }) else {
            XCTFail("same_ledger_diff_position case missing from oracle"); return
        }
        XCTAssertEqual(str(fk, "expect"), "fork")
        let (_, sign, verify) = try ledgerKeypair(0x41) // one ledger signs both conflicting positions (a partition)
        let rA = receiptFromJSON(dict(fk, "a"))
        let rB = receiptFromJSON(dict(fk, "b"))
        let sigA = try Approval.signConsumeReceipt(rA, sign)
        let sigB = try Approval.signConsumeReceipt(rB, sign)

        let resolve: (_ ledgerId: [UInt8]) -> Approval.Verify? = { id in id == rA.ledger ? verify : nil }
        let rs = Approval.ReceiptSet(resolve)
        XCTAssertNil(try rs.observe(rA, sigA), "first receipt flagged")
        let fe = try rs.observe(rB, sigB)
        guard let fe = fe else { XCTFail("fork not detected on same approval id / different positions"); return }
        XCTAssertNotEqual(fe.a.position, fe.b.position, "fork evidence hides the position conflict")
        XCTAssertNoThrow(try fe.verify(resolve), "fork evidence failed to verify")

        // a byte-identical re-emission is a benign duplicate, never flagged.
        let rs2 = Approval.ReceiptSet(resolve)
        _ = try rs2.observe(rA, sigA)
        XCTAssertNil(try rs2.observe(rA, sigA), "benign duplicate flagged")
    }

    // 4. (case b) two DIFFERENT ledgers each sign a receipt for the SAME approval id (a single-use
    //    approval spent twice), run concurrently on independent signed ledgers; observing both yields a
    //    provable contradiction.
    func testConsumeForkCrossLedger() throws {
        let c = try crVec()
        let ledgerAID = Self.hexToBytes(str(dict(c, "ledgers"), "a_hex"))
        let ledgerBID = Self.hexToBytes(str(dict(c, "ledgers"), "b_hex"))
        let approvalX = Self.hexToBytes(str(dict(c, "approvals"), "x_hex"))
        let (_, signA, verifyA) = try ledgerKeypair(0x41)
        let (_, signB, verifyB) = try ledgerKeypair(0x42)

        let lA = try Approval.Ledger.openLedgerSigned(Self.tempLedgerPath(), ledgerId: String(decoding: ledgerAID, as: UTF8.self), receiptSigner: signA)
        defer { try? lA.close() }
        let lB = try Approval.Ledger.openLedgerSigned(Self.tempLedgerPath(), ledgerId: String(decoding: ledgerBID, as: UTF8.self), receiptSigner: signB)
        defer { try? lB.close() }

        // Two independent ordering authorities, run concurrently, each consuming approval X on its own
        // signed ledger — each succeeds locally (they cannot see each other); the double spend is not
        // prevented, only made provable on comparison.
        let group = DispatchGroup()
        let collector = NSLock()
        var results: [(Approval.ConsumeReceipt, [UInt8])] = []
        for l in [lA, lB] {
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                if let (_, r, sig) = try? l.consumeWithReceipt(approvalX, "requester") {
                    collector.lock(); results.append((r, sig)); collector.unlock()
                }
            }
        }
        group.wait()
        XCTAssertEqual(results.count, 2, "both independent ledgers must consume locally")

        let resolve: (_ ledgerId: [UInt8]) -> Approval.Verify? = { id in
            id == ledgerAID ? verifyA : (id == ledgerBID ? verifyB : nil)
        }
        let rs = Approval.ReceiptSet(resolve)
        var forkEvidence: Approval.ConsumeForkEvidence? = nil
        for (r, sig) in results {
            if let fe = try rs.observe(r, sig) {
                forkEvidence = fe
            }
        }
        guard let fe = forkEvidence else { XCTFail("cross-ledger double spend not detected"); return }
        XCTAssertNotEqual(fe.a.ledger, fe.b.ledger, "cross-ledger fork evidence names the same ledger twice")
        XCTAssertNoThrow(try fe.verify(resolve), "cross-ledger fork evidence failed to verify")
    }

    // 5. (case c) THE COMPARE-AND-SET MUTATION ANCHOR. On ONE honest signed ledger, consuming the same
    //    approval id twice must yield exactly ONE ledger-signed receipt (first-append-wins): the first
    //    consume returns a receipt at position 0, the second returns AlreadyConsumed and mints nothing.
    //    If the CAS in consumeWithReceipt is mutated to always-succeed, the second consume mints a
    //    SECOND receipt at position 1 for the same approval id, so this assertion flips pass -> fail.
    func testConsumeFirstAppendWinsCAS() throws {
        let c = try crVec()
        let ledgerAID = Self.hexToBytes(str(dict(c, "ledgers"), "a_hex"))
        let approvalX = Self.hexToBytes(str(dict(c, "approvals"), "x_hex"))
        let (_, sign, verify) = try ledgerKeypair(0x41)
        let l = try Approval.Ledger.openLedgerSigned(Self.tempLedgerPath(), ledgerId: String(decoding: ledgerAID, as: UTF8.self), receiptSigner: sign)
        defer { try? l.close() }

        let resolve: (_ ledgerId: [UInt8]) -> Approval.Verify? = { id in id == ledgerAID ? verify : nil }
        let rs = Approval.ReceiptSet(resolve)

        // first consume wins with a receipt at the ledger's forward-only position 0.
        let (e1, r1, sig1) = try l.consumeWithReceipt(approvalX, "requester")
        XCTAssertEqual(e1.seq, 0, "first receipt position")
        XCTAssertEqual(r1.position, 0, "first receipt position")
        XCTAssertNil(try rs.observe(r1, sig1), "first receipt flagged")

        // second consume of the same id: AlreadyConsumed, signs nothing (first-append-wins).
        XCTAssertThrowsError(try l.consumeWithReceipt(approvalX, "requester"), "second consume of the same approval id succeeded (CAS is not first-append-wins)") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AlreadyConsumed")
        }
        XCTAssertEqual(l.len(), 1, "ledger has more than one entry")
    }

    // 6. N threads call consumeWithReceipt for the same approval id concurrently on ONE signed ledger;
    //    exactly one wins and mints exactly one receipt, the rest get AlreadyConsumed, and the fork
    //    detector sees no fork from the single winner.
    func testConsumeReceiptExactlyOnceUnderRace() throws {
        let c = try crVec()
        let ledgerAID = Self.hexToBytes(str(dict(c, "ledgers"), "a_hex"))
        let approvalX = Self.hexToBytes(str(dict(c, "approvals"), "x_hex"))
        let (_, sign, verify) = try ledgerKeypair(0x41)
        let l = try Approval.Ledger.openLedgerSigned(Self.tempLedgerPath(), ledgerId: String(decoding: ledgerAID, as: UTF8.self), receiptSigner: sign)
        defer { try? l.close() }

        let N = 64
        let cond = NSCondition()
        var go = false
        let counter = NSLock()
        var wins = 0, alreadys = 0, others = 0
        var winner: (Approval.ConsumeReceipt, [UInt8])? = nil
        let group = DispatchGroup()

        for _ in 0..<N {
            group.enter()
            let t = Thread {
                defer { group.leave() }
                cond.lock(); while !go { cond.wait() }; cond.unlock()
                do {
                    let (_, r, sig) = try l.consumeWithReceipt(approvalX, "requester")
                    counter.lock(); wins += 1; winner = (r, sig); counter.unlock()
                } catch let e as NaalpError where e.kind == "AlreadyConsumed" {
                    counter.lock(); alreadys += 1; counter.unlock()
                } catch {
                    counter.lock(); others += 1; counter.unlock()
                }
            }
            t.stackSize = 1 << 20
            t.start()
        }
        Thread.sleep(forTimeInterval: 0.05)
        cond.lock(); go = true; cond.broadcast(); cond.unlock()
        group.wait()

        XCTAssertEqual(others, 0, "no unexpected errors under the race")
        XCTAssertEqual(wins, 1, "exactly one thread wins the single-use consume-with-receipt")
        XCTAssertEqual(alreadys, N - 1, "the other N-1 threads get AlreadyConsumed")
        XCTAssertEqual(l.len(), 1, "the durable ledger recorded exactly one consume")

        guard let (r, sig) = winner else { XCTFail("no winner recorded"); return }
        let resolve: (_ ledgerId: [UInt8]) -> Approval.Verify? = { id in id == ledgerAID ? verify : nil }
        let rs = Approval.ReceiptSet(resolve)
        XCTAssertNil(try rs.observe(r, sig), "sole winning receipt flagged as a fork with itself")
    }

    // 7. section-4 wire cases: keys out of order (rejected NonCanonical at the CBOR layer, before any
    //    receipt rule), a position too large for a normal int (64-bit uint round-trip), and empty-value
    //    vs absent-value (empty != absent; empty ledger id is verify-rejected fail-closed).
    func testConsumeReceiptWireCases() throws {
        let c = try crVec()
        let wire = dict(c, "wire")

        // keys out of order -> the strict decoder rejects NonCanonical.
        let outOfOrder = dict(wire, "keys_out_of_order")
        let noncanon = Self.hexToBytes(str(outOfOrder, "payload_hex"))
        XCTAssertThrowsError(try Cbor.decode(noncanon), "non-canonical (keys 3,2,1) receipt body accepted by decoder") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "NonCanonical")
        }
        // the canonical variant of the same logical receipt decodes cleanly.
        XCTAssertNoThrow(try Cbor.decode(Self.hexToBytes(str(outOfOrder, "canonical_payload_hex"))), "canonical receipt body rejected")

        // position too large: a 64-bit uint position round-trips (encode == oracle, decode == value).
        let base = dict(c, "base")
        let ledgerX = Self.hexToBytes(str(base, "ledger_hex"))
        let approvalX = Self.hexToBytes(str(base, "approval_id_hex"))
        for big in arr(wire, "position_too_large") {
            let name = str(big, "name")
            let pos = u64(big, "position")
            let r = Approval.ConsumeReceipt(ledger: ledgerX, approvalID: approvalX, position: pos)
            XCTAssertEqual(Self.toHex(try r.bytes()), str(big, "body_hex"), "\(name) encode")
            let v = try Cbor.decode(Self.hexToBytes(str(big, "body_hex")))
            guard case let .m(pairs) = v else { XCTFail("\(name) not a map"); continue }
            var got: UInt64? = nil
            for (k, val) in pairs {
                if case .u(3) = k, case let .u(p) = val { got = p }
            }
            XCTAssertEqual(got, pos, "\(name) position round-trip")
        }

        // empty-ledger receipt: well-formed bytes (match the oracle) but verify-rejected fail-closed,
        // and its bytes differ from the absent-ledger variant (empty != absent).
        let el = dict(wire, "empty_ledger")
        let empty = Approval.ConsumeReceipt(ledger: [], approvalID: Self.hexToBytes(str(el, "approval_id_hex")), position: u64(el, "position"))
        XCTAssertEqual(Self.toHex(try empty.bytes()), str(el, "body_hex"), "empty-ledger body")
        let (_, _, verify) = try ledgerKeypair(0x41)
        XCTAssertThrowsError(try Approval.verifyConsumeReceipt(empty, verify, [UInt8](repeating: 0, count: 3309)), "empty-ledger receipt verified") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ConsumeReceiptUnsigned")
        }
        let absentBodyHex = str(dict(wire, "absent_ledger"), "body_hex")
        XCTAssertNotEqual(str(el, "body_hex"), absentBodyHex, "empty-ledger and absent-ledger receipts must encode to distinct bytes (empty != absent)")
    }

    // ================================================================================================
    // R-TDCS-5 (audience) + R-TDCS-3 (refusal), graded against vectors/trust_decision/cases.json
    // ================================================================================================

    // 8. an approval carrying the OPTIONAL audience field encodes byte-identically to the oracle, and a
    //    named audience is checked at use — a mismatched context is rejected, an absent audience passes
    //    any context, a matching one verifies.
    func testAudienceByteParityAndCheck() throws {
        let c = try tdVec()
        let a = dict(c, "audience")
        for tc in arr(a, "cases") {
            let rec = Approval.ApprovalRecord(
                approves: Self.hexToBytes(str(a, "approves_hex")), approver: str(a, "approver"),
                grant: u64(a, "grant"), nonce: Self.hexToBytes(str(a, "nonce_hex")), notAfter: u64(a, "not_after"),
                audience: str(tc, "audience"))
            XCTAssertEqual(Self.toHex(try rec.bytes()), str(tc, "record_hex"), "\(str(tc, "name")): approval bytes != oracle")
            XCTAssertEqual(Self.toHex(try rec.id()), str(tc, "approval_id_hex"), "\(str(tc, "name")): approval id != oracle")
        }

        // A named audience must NOT equal the absent-audience bytes — naming a context changes the
        // signed bytes, so a verdict cannot be silently moved to another context.
        let present = Approval.ApprovalRecord(approves: Self.hexToBytes(str(a, "approves_hex")), approver: str(a, "approver"),
                                              grant: u64(a, "grant"), nonce: Self.hexToBytes(str(a, "nonce_hex")), notAfter: u64(a, "not_after"),
                                              audience: str(a, "use_context_match"))
        let absent = Approval.ApprovalRecord(approves: Self.hexToBytes(str(a, "approves_hex")), approver: str(a, "approver"),
                                             grant: u64(a, "grant"), nonce: Self.hexToBytes(str(a, "nonce_hex")), notAfter: u64(a, "not_after"))
        XCTAssertNotEqual(try present.bytes(), try absent.bytes(), "naming an audience must change the approval bytes")

        // The check: a named audience must match the use context; an absent audience passes any context.
        XCTAssertNoThrow(try Approval.verifyAudience(present, str(a, "use_context_match")), "matching audience should verify")
        XCTAssertThrowsError(try Approval.verifyAudience(present, str(a, "use_context_mismatch")), "mismatched audience must be rejected") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "AudienceMismatch")
        }
        XCTAssertNoThrow(try Approval.verifyAudience(absent, str(a, "use_context_mismatch")), "an approval naming no audience must pass any context")
    }

    // 9. refusalFromRecord yields the exact oracle bytes for each closed-set outcome, carries the full
    //    record's content id, and NEVER carries the record's discriminating detail (the reason).
    //    parseRefusal round-trips a conformant refusal and rejects every non-conformant shape.
    func testRefusalCoarseAndNoLeak() throws {
        let c = try tdVec()
        let r = dict(c, "refusal")
        let fullRecord = Self.hexToBytes(str(r, "full_record_hex"))
        let recordID = Self.hexToBytes(str(r, "full_record_id_hex"))
        let reason = Array(str(r, "leaked_reason").utf8)

        for tc in arr(r, "cases") {
            let ref = Approval.refusalFromRecord(u64(tc, "outcome"), fullRecord)
            let b = try ref.bytes()
            XCTAssertEqual(Self.toHex(b), str(tc, "record_hex"), "\(str(tc, "name")): refusal bytes != oracle")
            // the record's reason must NOT appear anywhere in the party-visible refusal bytes.
            XCTAssertFalse(containsSubsequence(b, reason), "\(str(tc, "name")): the record's reason LEAKED into the party-visible refusal")
            XCTAssertTrue(containsSubsequence(b, recordID), "\(str(tc, "name")): refusal does not carry the full-record content id")
            // round-trip: a conformant refusal parses back to the same outcome + record id.
            let got = try Approval.parseRefusal(b)
            XCTAssertEqual(got.outcome, u64(tc, "outcome"), "\(str(tc, "name")): round-trip outcome")
            XCTAssertEqual(got.record, recordID, "\(str(tc, "name")): round-trip record")
        }

        // Non-conformant refusals a conformant parser MUST reject.
        let reject = dict(r, "reject")
        XCTAssertThrowsError(try Approval.parseRefusal(Self.hexToBytes(str(reject, "unknown_outcome_hex"))), "unknown refusal outcome must be rejected") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "UnknownRefusalOutcome")
        }
        for (name, hex) in [
            ("extra field (leaked detail)", str(reject, "detail_leak_extra_field_hex")),
            ("missing record id", str(reject, "missing_record_hex")),
            ("empty record id", str(reject, "empty_record_hex")),
        ] {
            XCTAssertThrowsError(try Approval.parseRefusal(Self.hexToBytes(hex)), "\(name) must be rejected") {
                XCTAssertEqual(($0 as? NaalpError)?.kind, "RefusalDetailLeak", name)
            }
        }
    }

    /// True iff `haystack` contains `needle` as a contiguous byte run (a hand-rolled substring search —
    /// no vector-graded surface here, just a KAT-support helper).
    private func containsSubsequence(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= haystack.count else { return needle.isEmpty }
        for start in 0...(haystack.count - needle.count) {
            if Array(haystack[start..<(start + needle.count)]) == needle { return true }
        }
        return false
    }

    // 10. THE RED-EVIDENCE MUTATION ANCHOR (structural, unconditional — no vector/crypto dependency
    //     beyond a pure closed-set membership test): isKnownRefusalOutcome must accept EXACTLY
    //     {0,1,2} and reject everything else. Neutering it to `return true` (or dropping the guard) is
    //     the mutation this test is designed to catch — see red_evidence entry for approval/swift.
    func testIsKnownRefusalOutcomeClosedSet() {
        XCTAssertTrue(Approval.isKnownRefusalOutcome(Approval.REFUSAL_DENIED), "denied (0) must be known")
        XCTAssertTrue(Approval.isKnownRefusalOutcome(Approval.REFUSAL_HELD), "held (1) must be known")
        XCTAssertTrue(Approval.isKnownRefusalOutcome(Approval.REFUSAL_UNVERIFIABLE), "unverifiable (2) must be known")
        XCTAssertFalse(Approval.isKnownRefusalOutcome(3), "3 is outside the closed set and must be rejected")
        XCTAssertFalse(Approval.isKnownRefusalOutcome(UInt64.max), "an arbitrary large code must be rejected")
    }

    // ================================================================================================
    // R-TDCS-4: freshness independence (synthetic scenario — the Go reference's tdcs_test.go is not
    // vector-graded either; graded here against real ML-DSA-65 ledger crypto + the existing Ed25519
    // approval demonstration).
    // ================================================================================================

    // 11. when the ordering authority is distinct from the authenticated party, an unexpired,
    //     correctly-signed approval with a valid ledger receipt verifies; when the ordering authority IS
    //     the authenticated party, it is rejected FreshnessSelfAsserted; the distinctness check does not
    //     weaken the underlying checks (an expired approval still fails); an unnamed ordering authority
    //     is not evidence.
    func testVerifyFreshIndependent() throws {
        let approverSeed = [UInt8](repeating: 0x11, count: 32)
        let approverPk = try Cose.ed25519PublicKey(approverSeed)
        let approverVerify: Approval.Verify = { msg, sig in Cose.ed25519Verify(approverPk, msg, sig) }
        let (_, ledgerSign, ledgerVerify) = try ledgerKeypair(0x22) // a DISTINCT key from the approver

        let argsID = Array("the-exact-canonical-args-content-id".utf8)
        let approverID = Array("approver-authenticated-party-id".utf8)
        let ledgerID = Array("ordering-authority-ledger-id".utf8)

        let a = Approval.ApprovalRecord(approves: argsID, approver: "approver-authenticated-party-id",
                                        grant: 1, nonce: Array("anti-replay-nonce".utf8), notAfter: 1000)
        let aSig = try Approval.signApproval(a, approverSeed)
        let r = Approval.ConsumeReceipt(ledger: ledgerID, approvalID: try a.id(), position: 7)
        let rSig = try Approval.signConsumeReceipt(r, ledgerSign)

        // Distinct ordering authority (party != ledger): verifies.
        XCTAssertNoThrow(try Approval.verifyFreshIndependent(a, approverVerify, aSig, argsID, 1000, r, ledgerVerify, rSig, approverID),
                         "distinct ordering authority should verify")

        // Self-asserted freshness (party == ledger): the party is the source of its own time — rejected.
        XCTAssertThrowsError(try Approval.verifyFreshIndependent(a, approverVerify, aSig, argsID, 1000, r, ledgerVerify, rSig, ledgerID),
                             "self-asserted freshness (party == ordering authority) must be rejected") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "FreshnessSelfAsserted")
        }

        // The distinctness check does not weaken the underlying checks: an expired approval still fails
        // closed, and a distinct authority does not rescue it.
        XCTAssertThrowsError(try Approval.verifyFreshIndependent(a, approverVerify, aSig, argsID, a.notAfter + 1, r, ledgerVerify, rSig, approverID),
                             "expired approval must still be rejected under a distinct authority") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ApprovalExpired")
        }

        // A receipt with no named ordering authority is not evidence, even when the party id supplied
        // is distinct.
        let (_, otherSign, _) = try ledgerKeypair(0x33)
        let empty = Approval.ConsumeReceipt(ledger: [], approvalID: try a.id(), position: 7)
        let emptySig = try Approval.signConsumeReceipt(empty, otherSign)
        XCTAssertThrowsError(try Approval.verifyFreshIndependent(a, approverVerify, aSig, argsID, 1000, empty, ledgerVerify, emptySig, approverID),
                             "unnamed ordering authority must not be accepted as freshness evidence") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "ConsumeReceiptUnsigned")
        }
    }

    // ================================================================================================
    // Port extra: openLedger (unsigned) alongside openLedgerSigned
    // ================================================================================================

    // 12. `openLedger` (the reference-named unsigned factory) offers `consume`/`consumeObject` but
    //     fails closed on `consumeWithReceipt` (LedgerUnsigned); `openLedgerSigned` refuses an EMPTY
    //     ledgerId fail-closed (an unnamed ordering authority cannot sign the anti-double-spend
    //     position); a properly-signed ledger mints a receipt that verifies under its own key.
    func testOpenLedgerAndOpenLedgerSignedFailClosed() throws {
        let plain = try Approval.Ledger.openLedger(Self.tempLedgerPath())
        defer { try? plain.close() }
        XCTAssertThrowsError(try plain.consumeWithReceipt(Array("approval-x".utf8), "by"), "unsigned ledger consumeWithReceipt accepted") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "LedgerUnsigned")
        }
        // the plain ledger still offers the unsigned Consume path.
        XCTAssertNoThrow(try plain.consume(Array("approval-x".utf8), "by"), "unsigned ledger consume should still work")

        let (_, sign, _) = try ledgerKeypair(0x61)
        XCTAssertThrowsError(try Approval.Ledger.openLedgerSigned(Self.tempLedgerPath(), ledgerId: "", receiptSigner: sign),
                             "empty ledgerId must be refused fail-closed") {
            XCTAssertEqual(($0 as? NaalpError)?.kind, "LedgerUnsigned")
        }

        let (_, sign2, verify2) = try ledgerKeypair(0x62)
        let signed = try Approval.Ledger.openLedgerSigned(Self.tempLedgerPath(), ledgerId: "authority-Z", receiptSigner: sign2)
        defer { try? signed.close() }
        let approvalID = Array("approval-y".utf8)
        let (entry, receipt, sig) = try signed.consumeWithReceipt(approvalID, "by")
        XCTAssertEqual(entry.seq, 0)
        XCTAssertEqual(receipt.position, 0)
        XCTAssertEqual(receipt.ledger, Array("authority-Z".utf8))
        XCTAssertNoThrow(try Approval.verifyConsumeReceipt(receipt, verify2, sig))
    }
}
