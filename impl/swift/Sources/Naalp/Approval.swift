// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C6 approval + the durable single-use consume ledger for the Swift SDK (design.md §7;
// R-7.1..7.4).
//
// An Approval binds, under signature, the content id of the exact canonical argument object it
// approves (§7.1): because the args are named by content id, mutating any argument changes the id and
// the approval no longer matches (ApprovalMismatch). The consume ledger is a durable, hash-chained,
// single-use compare-and-set set keyed by approval content id: the first consumer wins and a second
// consume of the same approval is rejected (AlreadyConsumed) (§7.2). Atomicity comes from a write-ahead
// log fsynced before a consume returns (persist-before-ack, R-7.2) and a single-writer lock that
// serialises the compare-and-set, so under a concurrent race exactly one consumer succeeds. A held
// outcome is a distinct, signed, non-success result (§7.4). Every rejection is fail-closed and causes
// no ledger append (§15).
//
// An independent transcription of impl/go/approval (cross-read against impl/python/naalp/approval.py),
// graded against the shared vectors/approval/cases.json. The approval body, the ledger entry body, and
// the chain head reuse the shared Naalp.Records builders — the same spine bytes the reference encodes,
// so the corpus grades byte-identical output.
//
// CRYPTO SCOPE — §7.1 core (unchanged, ApprovalTests.swift): the corpus-graded surfaces — the approval
// body/id, the ledger genesis head, each entry body + head_after + seq, the AlreadyConsumed replay, the
// final head, and the LedgerCorrupt broken-link rejection — are pure and signature-independent. The
// core approval/held-result SIGNATURES (`signApproval`/`verifyApproval`/`signHeld`) are demonstrated
// with a real Ed25519 (RFC 8032) sign/verify round-trip through an injected `(msg, sig) -> Bool`
// verifier — the reference's ML-DSA cross-language signed pins for THIS layer are not vector-pinned
// and are NOT reproduced here (honest F2/F4), mirroring the PHP port; this is unchanged by the addition
// below.
//
// CRYPTO SCOPE — §7.5 T1.5 addition (NAALP-REQ-121, this wave): the ledger-signed ConsumeReceipt /
// ConsumeForkEvidence / ReceiptSet layer, graded against vectors/consume_receipt/cases.json, signs and
// verifies with REAL deterministic ML-DSA-65 (MlDsa.swift, the CNaalpMldsa BoringSSL shim, #142) — Swift
// is NO LONGER pure-only for ML-DSA, so this layer is genuine cryptographic verification, not a stand-in
// (matching IdentityRecordsKatTests' use of MlDsa.verify). The audience (R-TDCS-5) and refusal (R-TDCS-3)
// surfaces, graded against vectors/trust_decision/cases.json, are pure (no signing).

import Crypto
import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

public enum Approval {

    /// The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is all-zero.
    public static let HEAD_SIZE = 48

    /// A `(msg, sig) -> Bool` signature verifier the pure-tier signature gates take by injection
    /// (Ed25519 on this pure Swift port; the reference resolves an ML-DSA verifier for the approver).
    public typealias Verify = (_ msg: [UInt8], _ sig: [UInt8]) -> Bool

    /// An injected consuming-ledger signer: `(msg) throws -> sig` (T1.5, NAALP-REQ-121). The consume-
    /// receipt layer signs and verifies with REAL ML-DSA-65 in this port (MlDsa.swift, #142) — the
    /// caller supplies the signer bound to the ordering authority's key.
    public typealias Signer = (_ msg: [UInt8]) throws -> [UInt8]

    // --- the Approval object body (§7.1) ---

    /// The body of an Approval object: it binds `approves` (the content id of the exact canonical args),
    /// the `approver` signer id, the granted effect class `grant` (the C5 effect), an anti-replay
    /// `nonce`, and the `notAfter` expiry (epoch ms). Signed with the C2 crypto over its
    /// deterministic-CBOR bytes.
    public struct ApprovalRecord {
        public let approves: [UInt8]
        public let approver: String
        public let grant: UInt64
        public let nonce: [UInt8]
        public let notAfter: UInt64
        /// OPTIONAL valid-context (R-TDCS-5, design.md §25); "" == absent (field 6 omitted,
        /// unrestricted by the issuer's explicit choice). Defaulted so every existing call site
        /// (which predates R-TDCS-5) keeps compiling and keeps encoding the 5-field body.
        public let audience: String

        public init(approves: [UInt8], approver: String, grant: UInt64, nonce: [UInt8], notAfter: UInt64, audience: String = "") {
            self.approves = approves
            self.approver = approver
            self.grant = grant
            self.nonce = nonce
            self.notAfter = notAfter
            self.audience = audience
        }

        /// Deterministic-CBOR encoding of the approval body {1: approves, 2: approver, 3: grant,
        /// 4: nonce, 5: not_after, ?6: audience}. Field 6 is OMITTED when `audience` is "" — an
        /// empty string is not a distinct value, so an approval naming no audience encodes
        /// byte-identically to a 5-field approval (R-TDCS-5, additive by design; byte-identical to
        /// the reference's ApprovalRecord.Bytes()).
        public func bytes() throws -> [UInt8] {
            var pairs: [(CborValue, CborValue)] = [
                (.u(1), .b(approves)),
                (.u(2), .t(approver)),
                (.u(3), .u(grant)),
                (.u(4), .b(nonce)),
                (.u(5), .u(notAfter)),
            ]
            if !audience.isEmpty {
                pairs.append((.u(6), .t(audience)))
            }
            return try Cbor.encode(.m(pairs))
        }

        /// The approval content id (the ledger key): multihash(0x20, SHA-384(body)).
        public func id() throws -> [UInt8] {
            return Cbor.contentId(try bytes())
        }
    }

    /// Ed25519 (RFC 8032) signing DEMONSTRATION of an approval body (pure Swift stands in for the
    /// reference's ML-DSA signer). Signs the deterministic-CBOR approval bytes with a 32-byte seed.
    public static func signApproval(_ a: ApprovalRecord, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try a.bytes())
    }

    /// Check that an approval (1) is signed by the approver's key, (2) binds the exact args by content
    /// id, and (3) has not expired at `posTime`. Returns normally only if all three hold; otherwise the
    /// specific named error and authorizes nothing. Does NOT consume — consumption is the separate
    /// atomic ledger step (§7.2). Check order mirrors the reference: signature -> args -> expiry.
    /// `verify` is the injected `(msg, sig) -> Bool` (Ed25519 on the pure Swift port).
    public static func verifyApproval(_ a: ApprovalRecord, _ verify: Verify, _ sig: [UInt8],
                                      _ argsContentID: [UInt8], _ posTime: UInt64) throws {
        if !verify(try a.bytes(), sig) {
            throw NaalpError("BadSignature", "approval signature does not verify")
        }
        if a.approves != argsContentID {
            throw NaalpError("ApprovalMismatch", "approval does not bind these arguments' content id")
        }
        if posTime > a.notAfter {
            throw NaalpError("ApprovalExpired", "approval is past its not_after")
        }
    }

    /// (R-TDCS-5, design.md §25) Enforces the OPTIONAL audience binding. An approval that NAMES an
    /// audience (`a.audience != ""`) is valid only in that context: a relying party checks it at use
    /// and rejects AudienceMismatch on a mismatch. An approval that names NO audience is unrestricted
    /// by the issuer's explicit choice and passes for any use context — a deployment MAY require an
    /// audience by local policy above this check. The check is mandatory WHEN a context is present,
    /// never mandatory-presence (the JWT `aud` present-optional / check-mandatory shape).
    public static func verifyAudience(_ a: ApprovalRecord, _ useContext: String) throws {
        if !a.audience.isEmpty && a.audience != useContext {
            throw NaalpError("AudienceMismatch", "approval names an audience other than the use context")
        }
    }

    // --- the held (not-yet-granted) outcome (§7.4) ---

    /// The distinct, signed, non-success result returned when an action requires an approval that has
    /// not been granted (§7.4). It is never a silent success or a silent denial. `reason` is a short
    /// accountable explanation.
    public struct HeldResult {
        public let approves: [UInt8]
        public let reason: String
        public init(approves: [UInt8], reason: String) {
            self.approves = approves
            self.reason = reason
        }

        /// Deterministic-CBOR encoding of the held result {1: approves, 2: reason}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(approves)),
                (.u(2), .t(reason)),
            ]))
        }
    }

    /// Ed25519 signing DEMONSTRATION of a held result, so the "not yet granted" outcome is attributable.
    public static func signHeld(_ h: HeldResult, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try h.bytes())
    }

    // --- the consume ledger (§7.2) ---

    /// One append to the consume ledger: {1: seq, 2: prev, 3: approval-id, 4: by}. The head after this
    /// entry is SHA-384(body); because the body carries `prev`, editing any entry breaks the next
    /// entry's linkage.
    public struct LedgerEntry {
        public let seq: UInt64
        public let prev: [UInt8]
        public let approvalID: [UInt8]
        public let by: String

        public init(seq: UInt64, prev: [UInt8], approvalID: [UInt8], by: String) {
            self.seq = seq
            self.prev = prev
            self.approvalID = approvalID
            self.by = by
        }

        /// Deterministic-CBOR encoding of the entry (the shared spine builder).
        public func bytes() throws -> [UInt8] {
            return try Records.ledgerEntry(seq, prev, approvalID, by)
        }
    }

    /// The chain head after an entry: SHA-384 of the entry body.
    static func chainNext(_ entryBytes: [UInt8]) -> [UInt8] {
        return Array(SHA384.hash(data: Data(entryBytes)))
    }

    /// The durable, hash-chained, single-use consume set (§7.2). All state mutation goes through
    /// `consume` under a single lock (the single-writer discipline), and each successful consume is
    /// written and fsynced to the write-ahead log before it returns (persist-before-ack), so exactly
    /// one concurrent consumer of a given approval id succeeds.
    public final class Ledger {
        private let lock = NSLock()
        private let fh: FileHandle
        private var consumedSet: [[UInt8]: UInt64] = [:]  // approval id -> seq
        private var headBytes: [UInt8]
        private var seqNum: UInt64
        private var closed = false
        // consuming-authority NAME (§2.5.3 audience target); also the T1.5 ordering-authority id when
        // set via `openLedgerSigned`, mirroring the reference's single `ledgerID` (unifying the
        // consumeObject audience check and the consume-receipt signing identity, exactly as Go/Rust do).
        private let ledgerId: String
        // T1.5 (NAALP-REQ-121): set only by `openLedgerSigned`; nil for a plain `open`/`openLedger`
        // (which offers `consume`/`consumeObject`, not `consumeWithReceipt`).
        private var receiptSigner: Signer? = nil

        private init(fh: FileHandle, authority: String) {
            self.fh = fh
            self.headBytes = [UInt8](repeating: 0, count: HEAD_SIZE)
            self.seqNum = 0
            self.ledgerId = authority
        }

        /// Open (creating if needed) a WAL-backed ledger at `path` and replay any existing log to
        /// rebuild the consumed set and chain head. A log that does not hash-chain cleanly is refused
        /// (LedgerCorrupt) rather than trusted.
        public static func open(_ path: String, authority: String = "") throws -> Ledger {
            if !FileManager.default.fileExists(atPath: path) {
                _ = FileManager.default.createFile(atPath: path, contents: nil)
            }
            guard let fh = FileHandle(forUpdatingAtPath: path) else {
                throw NaalpError("LedgerIO", "cannot open the consume-ledger WAL")
            }
            let l = Ledger(fh: fh, authority: authority)
            let data = (try? Data(contentsOf: URL(fileURLWithPath: path))) ?? Data()
            try l.replay([UInt8](data))
            return l
        }

        /// Replay the length-prefixed WAL (each record is a uint32 big-endian length then the entry
        /// body bytes), rebuilding state and verifying the hash chain: each record's seq must be the
        /// next expected value and its prev must link to the previous record's head. A truncated
        /// record, an out-of-order seq, or a broken link is LedgerCorrupt.
        private func replay(_ bytes: [UInt8]) throws {
            var pos = 0
            var head = [UInt8](repeating: 0, count: HEAD_SIZE)
            var seq: UInt64 = 0
            while pos < bytes.count {
                if pos + 4 > bytes.count {
                    throw NaalpError("LedgerCorrupt", "truncated length prefix")
                }
                let n = (UInt32(bytes[pos]) << 24) | (UInt32(bytes[pos + 1]) << 16)
                    | (UInt32(bytes[pos + 2]) << 8) | UInt32(bytes[pos + 3])
                pos += 4
                let recLen = Int(n)
                if pos + recLen > bytes.count {
                    throw NaalpError("LedgerCorrupt", "truncated ledger record")
                }
                let rec = Array(bytes[pos..<(pos + recLen)])
                pos += recLen
                let e = try Ledger.parseEntry(rec)
                if e.seq != seq || e.prev != head {
                    throw NaalpError("LedgerCorrupt", "consume-ledger hash chain does not verify")
                }
                consumedSet[e.approvalID] = e.seq
                head = chainNext(rec)
                seq += 1
            }
            self.headBytes = head
            self.seqNum = seq
        }

        /// Atomically consume an approval id exactly once. The first caller for a given id appends a
        /// ledger entry (written and fsynced to the WAL before returning) and returns it; every later
        /// caller for the same id throws AlreadyConsumed with no append. The single lock serialises
        /// concurrent callers, so under a race exactly one succeeds (no read-then-write TOCTOU).
        @discardableResult
        public func consume(_ approvalID: [UInt8], _ by: String) throws -> LedgerEntry {
            lock.lock()
            defer { lock.unlock() }
            if consumedSet[approvalID] != nil {
                throw NaalpError("AlreadyConsumed", "approval already consumed")
            }
            let e = LedgerEntry(seq: seqNum, prev: headBytes, approvalID: approvalID, by: by)
            let rec = try e.bytes()
            try append(framed(rec))          // persist-before-ack: nothing is recorded in memory on failure
            consumedSet[approvalID] = e.seq
            headBytes = chainNext(rec)
            seqNum += 1
            return e
        }

        /// Consume the approval for a consume-once OBJECT, enforcing the §2.5.3 audience binding at the
        /// choke point BEFORE the compare-and-set: the object's audience MUST name this ledger's
        /// consuming authority, or the object is rejected WrongAudience with no ledger append. An
        /// unnamed ledger (no authority) refuses LedgerUnsigned -- it cannot be the audience of any
        /// object. The audience check is NEVER inside Envelope.verify (a relay/auditor legitimately
        /// verifies objects addressed to others). Mirrors Go/Rust Ledger.ConsumeObject -- the authority
        /// is this port's ledger NAME.
        @discardableResult
        public func consumeObject(_ o: Envelope.Object, _ approvalID: [UInt8], _ by: String) throws -> LedgerEntry {
            if ledgerId.isEmpty {
                throw NaalpError("LedgerUnsigned", "ledger has no consuming authority")
            }
            // fail-closed, before the CAS: throws NaalpError("WrongAudience") and appends nothing
            try Envelope.checkAudience(o, ledgerId, true)
            return try consume(approvalID, by)
        }

        /// Whether an approval id has been consumed.
        public func isConsumed(_ approvalID: [UInt8]) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return consumedSet[approvalID] != nil
        }

        /// The current chain head (a copy).
        public func head() -> [UInt8] {
            lock.lock(); defer { lock.unlock() }
            return headBytes
        }

        /// The number of consumed approvals.
        public func len() -> Int {
            lock.lock(); defer { lock.unlock() }
            return consumedSet.count
        }

        /// Flush and close the WAL file. A consume after close fails-closed at the WAL write.
        public func close() throws {
            lock.lock(); defer { lock.unlock() }
            if closed { return }
            closed = true
            fh.closeFile()
        }

        // --- WAL framing + durable append ---

        /// A length-prefixed record: uint32 big-endian length, then the entry body bytes.
        private func framed(_ rec: [UInt8]) -> [UInt8] {
            let n = UInt32(rec.count)
            return [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                    UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] + rec
        }

        /// Append `payload` to the WAL and fsync it before returning (persist-before-ack). A failed or
        /// short write throws LedgerIO and the caller records nothing (fail-closed).
        private func append(_ payload: [UInt8]) throws {
            let fd = fh.fileDescriptor
            lseek(fd, 0, SEEK_END)
            var off = 0
            try payload.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                while off < payload.count {
                    let w = write(fd, base + off, payload.count - off)
                    if w <= 0 {
                        throw NaalpError("LedgerIO", "short write to the consume-ledger WAL")
                    }
                    off += w
                }
            }
            if fsync(fd) != 0 {
                throw NaalpError("LedgerIO", "fsync of the consume-ledger WAL failed")
            }
        }

        // --- entry decode ---

        /// Decode a ledger entry from its deterministic-CBOR bytes. A non-map, an unknown key, a
        /// mistyped field, or a missing field is a corrupt record (LedgerCorrupt, fail-closed).
        static func parseEntry(_ rec: [UInt8]) throws -> LedgerEntry {
            guard let v = try? Cbor.decode(rec), case let .m(pairs) = v else {
                throw NaalpError("LedgerCorrupt", "ledger entry is not canonical or not a map")
            }
            var seq: UInt64? = nil, prev: [UInt8]? = nil, approvalID: [UInt8]? = nil, by: String? = nil
            for (k, val) in pairs {
                guard case let .u(kk) = k else {
                    throw NaalpError("LedgerCorrupt", "non-uint ledger entry key")
                }
                switch kk {
                case 1:
                    guard case let .u(u) = val else { throw NaalpError("LedgerCorrupt", "seq not uint") }
                    seq = u
                case 2:
                    guard case let .b(b) = val else { throw NaalpError("LedgerCorrupt", "prev not bstr") }
                    prev = b
                case 3:
                    guard case let .b(b) = val else { throw NaalpError("LedgerCorrupt", "approval-id not bstr") }
                    approvalID = b
                case 4:
                    guard case let .t(s) = val else { throw NaalpError("LedgerCorrupt", "by not tstr") }
                    by = s
                default:
                    throw NaalpError("LedgerCorrupt", "unknown ledger entry key \(kk)")
                }
            }
            guard let s = seq, let p = prev, let a = approvalID, let b = by else {
                throw NaalpError("LedgerCorrupt", "ledger entry missing a required field")
            }
            return LedgerEntry(seq: s, prev: p, approvalID: a, by: b)
        }
    }
}

// ---- draft "## Approval state machine" (T20.1): the composed consume choke point --------------------
//
// PORTED from impl/go/approval/approval.go ConsumeApproval (mirrored in impl/rust/src/approval.rs
// consume_approval), graded against tools/approval_state_oracle.py (F3) via the adapter's
// `approval.state` op.
extension Approval {

    /// The composed, single-call consume choke point for the approval state machine (draft "##
    /// Approval state machine"). It runs the table's precedence in ONE place — the exact sequence a
    /// caller would otherwise hand-assemble — so a caller (and the conformance suite) drives one
    /// realization of the reactions rather than re-deriving the ordering at each call site:
    ///
    ///  1. `verifyApproval` checks the signature, then the args-content-id binding (ApprovalMismatch,
    ///     which the draft says takes precedence over every cell), then expiry (ApprovalExpired) —
    ///     all BEFORE the ledger. So a request both past `notAfter` AND already in the ledger is
    ///     refused ApprovalExpired, never AlreadyConsumed (the draft's expiry-over-consume rule),
    ///     leaving the ledger untouched.
    ///  2. The granted effect must be a valid class (0..3) and must cover the action's required
    ///     effect; a grant outside the closed vocabulary, or below the required effect, authorizes
    ///     nothing and is refused ApprovalRequired (fail-closed; the grant-range guard is stricter
    ///     than a raw caller).
    ///  3. The atomic single-use consume through the §7 ledger: the first consumer of the id wins, a
    ///     second throws AlreadyConsumed, and neither a rejected earlier step nor a losing race
    ///     appends.
    ///
    /// Every rejection is fail-closed and appends nothing; it consumes only when every check holds,
    /// returning the ledger entry. It does NOT enforce object audience — that is `consumeObject`'s
    /// binding (design.md §2.5.3).
    @discardableResult
    public static func consumeApproval(_ a: ApprovalRecord, _ verify: Verify, _ sig: [UInt8],
                                       _ argsContentID: [UInt8], _ posTime: UInt64,
                                       _ requiredEffect: Int, _ ledger: Ledger, _ by: String) throws -> LedgerEntry {
        try verifyApproval(a, verify, sig, argsContentID, posTime) // sig/mismatch/expiry, all before the ledger
        if a.grant > UInt64(Policy.DESTRUCTIVE) {
            throw NaalpError("ApprovalRequired", "action requires an approval that is not present") // grant outside the closed 0..3 vocabulary authorizes nothing
        }
        if !Policy.authorizes(Int(a.grant), requiredEffect) {
            throw NaalpError("ApprovalRequired", "action requires an approval that is not present") // the approval's granted effect does not cover this action
        }
        return try ledger.consume(try a.id(), by)
    }
}

// ---- R-TDCS-3 (design.md §25, C22): the party-visible coarse refusal object -----------------------
//
// A refusal returned to the authenticated party carries ONLY a single value from a closed vocabulary
// and the content id of the full signed record that carries the discriminating detail — a reference,
// not the reason. The detail exists, is signed, and is auditor-resolvable through the record channel,
// but never reaches the adversary-facing surface, so repeated refusals cannot serve an adaptive party
// as an oracle. A party-visible refusal that carries discriminating detail, or omits the record content
// id, is a RefusalDetailLeak; an outcome outside the closed set is UnknownRefusalOutcome. PORTED from
// impl/go/approval/refusal.go (the reference), graded against vectors/trust_decision/cases.json (F3).
extension Approval {

    /// The closed refusal-outcome set (CDDL refusal-outcome).
    public static let REFUSAL_DENIED: UInt64 = 0        // the action is refused
    public static let REFUSAL_HELD: UInt64 = 1          // the action requires a further step not yet taken
    public static let REFUSAL_UNVERIFIABLE: UInt64 = 2  // required evidence did not verify

    private static let knownRefusalOutcomes: Set<UInt64> = [REFUSAL_DENIED, REFUSAL_HELD, REFUSAL_UNVERIFIABLE]

    /// Reports whether `code` is in the closed refusal-outcome set. FAIL-CLOSED ANCHOR: this is the
    /// gate ParseRefusal relies on — an outcome outside {0,1,2} MUST NOT be treated as known.
    public static func isKnownRefusalOutcome(_ code: UInt64) -> Bool {
        return knownRefusalOutcomes.contains(code)
    }

    /// The party-visible coarse refusal body {1: outcome, 2: record}. `outcome` is the closed-set
    /// coarse outcome; `record` is the T1 content id of the full signed record carrying the detail.
    public struct Refusal {
        public let outcome: UInt64
        public let record: [UInt8]

        public init(outcome: UInt64, record: [UInt8]) {
            self.outcome = outcome
            self.record = record
        }

        /// Deterministic-CBOR encoding {1: outcome, 2: record}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .u(outcome)),
                (.u(2), .b(record)),
            ]))
        }
    }

    /// Builds the party-visible refusal for a full signed record: it carries the coarse outcome and
    /// the content id of `fullRecord`, and NOTHING drawn from inside `fullRecord` — the discriminating
    /// detail stays in the record, referenced only by its id. The coarse-to-party split R-TDCS-3
    /// requires.
    public static func refusalFromRecord(_ outcome: UInt64, _ fullRecord: [UInt8]) -> Refusal {
        return Refusal(outcome: outcome, record: Cbor.contentId(fullRecord))
    }

    /// Reconstructs a Refusal from its body bytes, enforcing that a party-visible refusal carries
    /// ONLY {outcome, record} and nothing more (R-TDCS-3). Rejects, fail-closed: a malformed/non-
    /// canonical body, any key other than 1 and 2, a missing or empty record id (RefusalDetailLeak —
    /// discriminating detail leaked, or the auditor reference dropped), and an outcome outside the
    /// closed set (UnknownRefusalOutcome). Authorizes nothing.
    public static func parseRefusal(_ b: [UInt8]) throws -> Refusal {
        guard let v = try? Cbor.decode(b), case let .m(pairs) = v else {
            throw NaalpError("RefusalDetailLeak", "refusal body is not canonical or not a map")
        }
        var outcome: UInt64? = nil
        var record: [UInt8]? = nil
        for (k, val) in pairs {
            guard case let .u(kk) = k else {
                throw NaalpError("RefusalDetailLeak", "non-uint refusal key")
            }
            switch kk {
            case 1:
                guard case let .u(u) = val else { throw NaalpError("RefusalDetailLeak", "outcome not uint") }
                outcome = u
            case 2:
                guard case let .b(rb) = val else { throw NaalpError("RefusalDetailLeak", "record not bstr") }
                record = rb
            default:
                throw NaalpError("RefusalDetailLeak", "any field beyond {1,2} is leaked detail")
            }
        }
        guard let o = outcome, let r = record, !r.isEmpty else {
            throw NaalpError("RefusalDetailLeak", "a refusal must carry the full-record content id")
        }
        guard isKnownRefusalOutcome(o) else {
            throw NaalpError("UnknownRefusalOutcome", "refusal outcome is outside the closed set denied/held/unverifiable")
        }
        return Refusal(outcome: o, record: r)
    }
}

// ---- T1.5 (NAALP-REQ-121, design.md §7.5): ledger-signed consume receipt / fork evidence -----------
//
// The anti-double-spend counter (Position) rides under the CONSUMING LEDGER's signature, never the
// requester's: the requester cannot forge the ledger's position or its signature. A partition that
// spends one approval twice therefore leaves two ledger-signed receipts against one approval id, each
// carrying a position drawn from forked state — a contradiction authored by neither the requester nor a
// thief, provable the instant the two receipts are compared (ConsumeForkEvidence). It does not PREVENT
// the second spend; it makes the double-spend detectable in bytes neither party could repudiate. PORTED
// from impl/go/approval/approval.go (the reference), graded against vectors/consume_receipt/cases.json
// (F3) with REAL ML-DSA-65 signatures (MlDsa.swift, #142) — Go == Rust == Swift == oracle bytes.
extension Approval {

    /// The ledger-signed evidence body {1: ledger, 2: approval_id, 3: position} that a consuming
    /// ledger bound an approval content id to its own forward-only position.
    public struct ConsumeReceipt {
        public let ledger: [UInt8]       // the consuming ledger's signer id (the ordering authority)
        public let approvalID: [UInt8]   // the approval content id consumed (the compare-and-set key)
        public let position: UInt64      // the ledger's forward-only position bound to this consume

        public init(ledger: [UInt8], approvalID: [UInt8], position: UInt64) {
            self.ledger = ledger
            self.approvalID = approvalID
            self.position = position
        }

        /// Deterministic-CBOR encoding {1: ledger, 2: approval_id, 3: position} — the exact bytes the
        /// ledger signs.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(ledger)),
                (.u(2), .b(approvalID)),
                (.u(3), .u(position)),
            ]))
        }
    }

    /// Signs a consume receipt with the LEDGER's key (REQ-121: the anti-double-spend counter is under
    /// the ordering authority's signature). The signed input is `r.bytes()`.
    public static func signConsumeReceipt(_ r: ConsumeReceipt, _ sign: Signer) throws -> [UInt8] {
        return try sign(try r.bytes())
    }

    /// Checks that a consume receipt is a valid ledger-signed statement: the ledger id is present (an
    /// unnamed ordering authority is not evidence) and the signature verifies under the ledger's key.
    /// FAIL-CLOSED: either fault throws ConsumeReceiptUnsigned and authorizes nothing. `verify` MUST be
    /// the verifier resolved for `r.ledger`.
    public static func verifyConsumeReceipt(_ r: ConsumeReceipt, _ verify: Verify, _ sig: [UInt8]) throws {
        if r.ledger.isEmpty {
            throw NaalpError("ConsumeReceiptUnsigned", "an unnamed ordering authority is not evidence")
        }
        if !verify(try r.bytes(), sig) {
            throw NaalpError("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify")
        }
    }

    /// Non-repudiable evidence that ONE approval content id received TWO conflicting ledger-signed
    /// consume receipts — a double spend made provable on comparison. It carries both receipts and both
    /// ledger signatures; because a verifier checks each signature under the key its receipt names, the
    /// contradiction is authored by neither the requester nor a thief.
    public struct ConsumeForkEvidence {
        public let approvalID: [UInt8]  // the one approval content id spent twice
        public let a: ConsumeReceipt    // first receipt
        public let sigA: [UInt8]        // ledger A's signature over a.bytes()
        public let b: ConsumeReceipt    // second receipt (same approval id; different position/ledger)
        public let sigB: [UInt8]        // ledger B's signature over b.bytes()

        public init(approvalID: [UInt8], a: ConsumeReceipt, sigA: [UInt8], b: ConsumeReceipt, sigB: [UInt8]) {
            self.approvalID = approvalID
            self.a = a
            self.sigA = sigA
            self.b = b
            self.sigB = sigB
        }

        /// Checks that `self` is a genuine fork: (1) the disputed approval id is present and BOTH
        /// receipts name it; (2) the two receipts actually conflict — they are NOT byte-identical (a
        /// byte-identical re-emission is a benign duplicate, not a fork); and (3) BOTH ledger signatures
        /// verify under the keys their receipts name, resolved through `resolve`. Any failure rejects
        /// the whole thing (fail-closed): a mismatched/absent approval id or a byte-identical pair is
        /// ConsumeForkInvalid, and an unnamed/unresolvable ledger or a signature that does not verify is
        /// ConsumeReceiptUnsigned. On a clean pass the double spend is proven and non-repudiable.
        public func verify(_ resolve: (_ ledgerId: [UInt8]) -> Approval.Verify?) throws {
            if approvalID.isEmpty {
                throw NaalpError("ConsumeForkInvalid", "fork evidence does not prove a double spend")
            }
            if a.approvalID != approvalID || b.approvalID != approvalID {
                throw NaalpError("ConsumeForkInvalid", "both receipts must name the one disputed approval id")
            }
            let ab = try a.bytes()
            let bb = try b.bytes()
            if ab == bb {
                throw NaalpError("ConsumeForkInvalid", "byte-identical receipts are a benign duplicate, not a fork")
            }
            guard !a.ledger.isEmpty, let va = resolve(a.ledger) else {
                throw NaalpError("ConsumeReceiptUnsigned", "ledger A is unnamed or unresolvable")
            }
            guard !b.ledger.isEmpty, let vb = resolve(b.ledger) else {
                throw NaalpError("ConsumeReceiptUnsigned", "ledger B is unnamed or unresolvable")
            }
            if !va(ab, sigA) || !vb(bb, sigB) {
                throw NaalpError("ConsumeReceiptUnsigned", "a ledger signature does not verify")
            }
        }
    }

    /// A receipt the ReceiptSet has accepted, kept with its signature so a later conflict can be minted
    /// into a ConsumeForkEvidence carrying BOTH ledger signatures.
    private struct SeenConsumeReceipt {
        let r: ConsumeReceipt
        let sig: [UInt8]
    }

    /// Observes ledger-signed consume receipts, keyed by approval content id, and detects a fork (a
    /// double spend) from the signed receipts alone — the consume-layer analogue of Audit.Auditor's
    /// equivocation detection (mirrors that established Swift idiom: `observe` throws only on an
    /// unverifiable receipt, and returns the fork evidence rather than throwing it, exactly like
    /// Audit.Auditor.observe returns `ForkProof?`). It resolves each receipt's ledger verifier through
    /// the `resolve` closure supplied at construction (the Swift equivalent of the reference's
    /// `NewReceiptSet`).
    public final class ReceiptSet {
        private let resolve: (_ ledgerId: [UInt8]) -> Verify?
        private var seen: [[UInt8]: SeenConsumeReceipt] = [:]

        /// Makes a fork detector that resolves a ledger id to its verifier via `resolve` (which
        /// returns nil for an unknown ledger id).
        public init(_ resolve: @escaping (_ ledgerId: [UInt8]) -> Verify?) {
            self.resolve = resolve
        }

        /// Records a ledger-signed consume receipt. Throws ConsumeReceiptUnsigned if the ledger is
        /// unnamed/unresolvable or the signature does not verify. Returns a ConsumeForkEvidence when a
        /// previously-seen receipt for the same approval id conflicts (different position and/or
        /// ledger); nil otherwise (including a benign byte-identical duplicate).
        public func observe(_ r: ConsumeReceipt, _ sig: [UInt8]) throws -> ConsumeForkEvidence? {
            let body = try r.bytes()
            guard !r.ledger.isEmpty, let v = resolve(r.ledger), v(body, sig) else {
                throw NaalpError("ConsumeReceiptUnsigned", "consume receipt is unnamed or its ledger signature does not verify")
            }
            if let prev = seen[r.approvalID] {
                if try prev.r.bytes() == body {
                    return nil // benign byte-identical duplicate
                }
                return ConsumeForkEvidence(approvalID: r.approvalID, a: prev.r, sigA: prev.sig, b: r, sigB: sig)
            }
            seen[r.approvalID] = SeenConsumeReceipt(r: r, sig: sig)
            return nil
        }
    }
}

// ---- R-TDCS-4 (design.md §25, C22): trust-decision closure sovereignty — freshness independence ----
extension Approval {

    /// (R-TDCS-4) Judges an approval's present-moment validity using time drawn from an ordering
    /// authority STRUCTURALLY DISTINCT from the party being authenticated. It is the named realization
    /// of the §18.2 seam — "validity judged on the ordering position, never the signer's clock" —
    /// composing the existing verifiers and adding the distinctness check a relying party runs so a
    /// party can never be the source of the time against which its own credential's expiry is judged.
    /// It (1) verifies the approval binds `argsContentID`, is signed by the approver, and is unexpired
    /// at `posTime`, where `posTime` is the ORDERING AUTHORITY's forward-only position (never a clock
    /// the approver supplies); (2) verifies the consume receipt is ledger-signed (the position rides
    /// under the ordering authority's key, never the requester's); and (3) rejects
    /// FreshnessSelfAsserted when the ordering authority `r.ledger` IS the authenticated party
    /// `partyID`. FAIL-CLOSED: any fault throws its named error and authorizes nothing.
    public static func verifyFreshIndependent(_ a: ApprovalRecord, _ approverVerify: Verify, _ aSig: [UInt8],
                                              _ argsContentID: [UInt8], _ posTime: UInt64,
                                              _ r: ConsumeReceipt, _ ledgerVerify: Verify, _ rSig: [UInt8],
                                              _ partyID: [UInt8]) throws {
        try verifyApproval(a, approverVerify, aSig, argsContentID, posTime)
        try verifyConsumeReceipt(r, ledgerVerify, rSig)
        if r.ledger == partyID {
            throw NaalpError("FreshnessSelfAsserted", "the ordering authority that stamps freshness is the authenticated party itself")
        }
    }
}

// ---- T1.5 (NAALP-REQ-121): the unsigned/signed ledger factories + the signed consume-with-receipt ---
//
// PORT EXTRA (task #174 launch note): the reference exposes BOTH `OpenLedger` (plain, unsigned — offers
// `Consume`/`ConsumeObject` only, both fail-closed on the T1.5 receipt surfaces) and `OpenLedgerSigned`
// (binds the ledger's own ordering-authority identity + signing key, unlocking `ConsumeWithReceipt`).
// This port's `open(_:authority:)` already served the unsigned case; `openLedger` is added here as the
// reference-named alias so both factories are discoverable by name, and `openLedgerSigned` adds the
// missing signed-ledger construction + `consumeWithReceipt`.
extension Approval.Ledger {

    /// Opens (creating if needed) a plain, UNSIGNED WAL-backed ledger — the Consume-only path (§7.2).
    /// Mirrors the reference's `OpenLedger`: no ordering-authority identity and no signer, so
    /// `consumeObject` and `consumeWithReceipt` both throw LedgerUnsigned fail-closed.
    public static func openLedger(_ path: String) throws -> Approval.Ledger {
        return try open(path)
    }

    /// Opens a WAL-backed ledger (as `openLedger`) bound to its own ordering-authority identity
    /// `ledgerId` and a `receiptSigner`, so it can produce ledger-signed consume receipts (T1.5,
    /// NAALP-REQ-121) AND enforce the §2.5.3 audience binding via `consumeObject` (the reference unifies
    /// both under one `ledgerID`; this port does the same). An empty `ledgerId` is refused fail-closed:
    /// an unnamed or keyless ordering authority cannot sign the anti-double-spend position. Mirrors the
    /// reference's `OpenLedgerSigned`.
    public static func openLedgerSigned(_ path: String, ledgerId: String, receiptSigner: @escaping Approval.Signer) throws -> Approval.Ledger {
        if ledgerId.isEmpty {
            throw NaalpError("LedgerUnsigned", "ledger was not opened with a signing key")
        }
        let l = try open(path, authority: ledgerId)
        l.receiptSigner = receiptSigner
        return l
    }

    /// Performs the first-append-wins compare-and-set (exactly as `consume`) AND, on the winning
    /// append, returns a ledger-signed ConsumeReceipt binding the approval id to the entry's
    /// forward-only position (its ledger seq). The ledger must have been opened with
    /// `openLedgerSigned`; a plain ledger throws LedgerUnsigned (fail-closed). A second consume of the
    /// same approval id throws AlreadyConsumed and signs nothing — the first receipt stands
    /// (first-append-wins). The receipt is signed BEFORE the WAL write, so a signing failure records
    /// nothing. The single lock serialises concurrent callers, so under a race exactly one wins and
    /// exactly one receipt is minted.
    @discardableResult
    public func consumeWithReceipt(_ approvalID: [UInt8], _ by: String) throws -> (entry: Approval.LedgerEntry, receipt: Approval.ConsumeReceipt, sig: [UInt8]) {
        lock.lock()
        defer { lock.unlock() }
        guard let sign = receiptSigner, !ledgerId.isEmpty else {
            throw NaalpError("LedgerUnsigned", "ledger was not opened with a signing key")
        }
        if consumedSet[approvalID] != nil {
            throw NaalpError("AlreadyConsumed", "approval already consumed") // first-append-wins: no second receipt
        }
        let e = Approval.LedgerEntry(seq: seqNum, prev: headBytes, approvalID: approvalID, by: by)
        // The receipt binds the approval id to THIS consume's forward-only position (the entry seq),
        // signed by the ledger key. Sign BEFORE touching the WAL so a signing failure records nothing.
        let receipt = Approval.ConsumeReceipt(ledger: Array(ledgerId.utf8), approvalID: approvalID, position: e.seq)
        let sig = try sign(try receipt.bytes())
        let rec = try e.bytes()
        try append(framed(rec))
        consumedSet[approvalID] = e.seq
        headBytes = Approval.chainNext(rec)
        seqNum += 1
        return (e, receipt, sig)
    }
}
