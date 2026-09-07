// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C21 NAALP-PAY payment import for the Swift SDK (design.md §24; R-PAY-1..6).
//
// NAALP-PAY imports a foreign payment payload — an AP2 mandate, an Agentic Commerce Protocol delegated
// token, an x402 payload — octet-for-octet as OPAQUE foreign bytes (carriage, not adoption): the foreign
// bytes are never re-serialized, canonicalized, or rewritten, and a foreign identity inside them never
// becomes an N-AALP authorization identity. It introduces NO new envelope, encoding, signature, identity,
// effect, or ledger mechanism: the imported payload becomes a value-bearing charge that N-AALP governs
// with its OWN added guarantees, reusing the closed C5 effect lattice (Naalp.Policy). There is NO fifth
// effect and NO payment-specific ledger.
//
// The added guarantees over the imported formats:
//   - PaymentImport {1: format, 2: amount, 3: currency, 4: payee, 5: not_after, 6: foreign} is the
//     wrapper body. `format` selects the imported FORMAT from the closed payment-format registry;
//     `foreign` carries the imported payload octet-for-octet. An unknown format is rejected
//     (UnknownPaymentFormat).
//   - THE CHARGE IS BOUND. ChargeBinding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
//     6: foreign_id} names the exact value a §7 approval binds by content id — including the foreign
//     payload's content id (the carriage binding). A wrong-amount, wrong-payee, wrong-currency, or
//     substituted-payload charge yields a different content id and no longer matches the approval.
//
// Every check is fail-closed (§15): a failing charge is rejected whole and returns its named error.
//
// An independent transcription of impl/go/payment (cross-read against impl/python/naalp/payment.py),
// graded against the shared vectors/payment/cases.json.
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces — the closed format registry, the PaymentImport
// and ChargeBinding body/head/content-id (incl. the >2^53 amount), the parse round-trip, the fail-closed
// edges, and the mismatch content-ids — are pure and signature-independent. Swift cannot deterministically
// sign or verify ML-DSA (FIPS 204) through the general envelope/COSE_Sign1 verification path used here
// (see Cose.swift/Envelope.swift), so the reference's ML-DSA PaymentImport signature is demonstrated with
// a real Ed25519 (RFC 8032) signature; the profile floor is level 3, so verifyPaymentImport correctly
// floors a pure-Ed25519 (level-0) object (ProfileDowngrade) and refuses an ML-DSA object at the signature
// step rather than fake a result.
//
// AuthorizeCharge (this wave) composes the real §7 approval + single-use consume ledger landed alongside
// this port (Naalp.Approval: ApprovalRecord, verifyApproval, Ledger.consume) and the shared C5 effect
// lattice (Naalp.Policy.authorizes) — reusing them UNCHANGED, exactly as impl/go/payment.AuthorizeCharge
// does. All four deny paths (UnknownPaymentFormat, the VerifyApproval failures ApprovalMismatch /
// ApprovalExpired / BadSignature, ApprovalRequired for an under-granting approval, AlreadyConsumed on
// replay) and the success-consumes-exactly-once path are graded in PaymentTests against
// vectors/payment/cases.json's charge-binding and mismatch vectors. The approval/consume-receipt
// SIGNATURES reused here are Ed25519-demonstrated (Approval.swift's own documented crypto scope); the
// reference's ML-DSA cross-language signed pins for that layer are not vector-pinned and are not
// reproduced here (honest F2/F4, unchanged from Approval.swift).

import Crypto
import Foundation

public enum Payment {

    /// The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    public static let HEAD_SIZE = 48

    /// The C5 effect a payment spend carries: a non_idempotent_write (no fifth effect). A charge is
    /// value-bearing and not safely repeatable, which is why it is spent single-use through the §7
    /// ledger (the ledger flow itself is out of scope this wave — see the file header).
    public static let CHARGE_EFFECT = Policy.NON_IDEMPOTENT_WRITE

    // Payment format codes (design §24; the closed payment-format registry).
    public static let FORMAT_AP2_MANDATE: UInt64 = 1 // AP2 mandate
    public static let FORMAT_ACP_TOKEN: UInt64 = 2   // Agentic Commerce Protocol delegated token
    public static let FORMAT_X402: UInt64 = 3        // x402 payload

    static let formatNames: [UInt64: String] = [
        FORMAT_AP2_MANDATE: "ap2-mandate",
        FORMAT_ACP_TOKEN: "acp-delegated-token",
        FORMAT_X402: "x402-payload",
    ]

    /// Whether code is one of the closed payment formats.
    public static func isRegisteredFormat(_ code: UInt64) -> Bool {
        return formatNames[code] != nil
    }

    /// The registry name of a format code, or "unknown".
    public static func formatName(_ code: UInt64) -> String {
        return formatNames[code] ?? "unknown"
    }

    static func head(_ b: [UInt8]) -> [UInt8] {
        return Array(SHA384.hash(data: Data(b)))
    }

    /// Wraps a foreign payment payload as a value-bearing charge. `format` selects the imported format
    /// (closed registry); `amount`/`currency`/`payee`/`notAfter` are the bound charge terms; `foreign`
    /// is the imported payload carried octet-for-octet (carriage, not adoption).
    public struct PaymentImport {
        public let format: UInt64
        public let amount: UInt64
        public let currency: String
        public let payee: [UInt8]
        public let notAfter: UInt64
        public let foreign: [UInt8]

        public init(format: UInt64, amount: UInt64, currency: String, payee: [UInt8], notAfter: UInt64, foreign: [UInt8]) {
            self.format = format
            self.amount = amount
            self.currency = currency
            self.payee = payee
            self.notAfter = notAfter
            self.foreign = foreign
        }

        /// Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
        /// 6: foreign}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .u(format)),
                (.u(2), .u(amount)),
                (.u(3), .t(currency)),
                (.u(4), .b(payee)),
                (.u(5), .u(notAfter)),
                (.u(6), .b(foreign)),
            ]))
        }

        /// The SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Payment.head(try bytes()) }

        /// The T1 content-id (50 octets): multihash(0x20, SHA-384(body)).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }

        /// The T1 content-id of the carried foreign payload — the hash the charge binding binds (the
        /// carriage binding). A substituted payload yields a different foreign-id.
        public func foreignId() -> [UInt8] { return Cbor.contentId(foreign) }

        /// The exact charge value an approval binds for this import (amount + currency + payee + expiry +
        /// the foreign payload's content id). A change to any bound term — including the foreign payload —
        /// changes the binding's content id.
        public func chargeBinding() -> ChargeBinding {
            return ChargeBinding(format: format, amount: amount, currency: currency,
                                 payee: payee, notAfter: notAfter, foreignId: foreignId())
        }
    }

    /// Names the exact charge by value: format, amount, currency, payee, expiry, and the foreign payload's
    /// content id. A §7 approval binds THIS binding's content id, so a change to any bound term
    /// invalidates a prior approval (ApprovalMismatch).
    public struct ChargeBinding {
        public let format: UInt64
        public let amount: UInt64
        public let currency: String
        public let payee: [UInt8]
        public let notAfter: UInt64
        public let foreignId: [UInt8] // content-id of the foreign payload: multihash(0x20, SHA-384(foreign))

        public init(format: UInt64, amount: UInt64, currency: String, payee: [UInt8], notAfter: UInt64, foreignId: [UInt8]) {
            self.format = format
            self.amount = amount
            self.currency = currency
            self.payee = payee
            self.notAfter = notAfter
            self.foreignId = foreignId
        }

        /// Deterministic-CBOR encoding {1: format, 2: amount, 3: currency, 4: payee, 5: not_after,
        /// 6: foreign_id}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .u(format)),
                (.u(2), .u(amount)),
                (.u(3), .t(currency)),
                (.u(4), .b(payee)),
                (.u(5), .u(notAfter)),
                (.u(6), .b(foreignId)),
            ]))
        }

        /// The SHA-384 head (48 octets).
        public func head() throws -> [UInt8] { return Payment.head(try bytes()) }

        /// The charge content id an approval binds: multihash(0x20, SHA-384(binding)).
        public func contentId() throws -> [UInt8] { return Cbor.contentId(try bytes()) }
    }

    // --- deterministic-CBOR field accessors (mirror impl/go/payment) ---

    static func field(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> CborValue? {
        for (key, val) in pairs {
            if case let .u(kk) = key, kk == k { return val }
        }
        return nil
    }

    static func uintField(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> UInt64? {
        if case let .u(x)? = field(pairs, k) { return x }
        return nil
    }

    static func tstrField(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> String? {
        if case let .t(x)? = field(pairs, k) { return x }
        return nil
    }

    static func bstrField(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> [UInt8]? {
        if case let .b(x)? = field(pairs, k) { return x }
        return nil
    }

    /// Reconstruct a PaymentImport from its body bytes alone. Does NOT validate the format against the
    /// closed set (that is verifyPaymentImport's job), so an import carrying an unknown format can be
    /// represented (and then rejected). Fail-closed (PayMalformed) on a non-canonical encoding, a
    /// non-map, or a missing/mistyped field 1-6.
    public static func parsePaymentImport(_ b: [UInt8]) throws -> PaymentImport {
        let v: CborValue
        do {
            v = try Cbor.decode(b) // the strict decoder rejects a non-canonical body (NonCanonical)
        } catch {
            throw NaalpError("PayMalformed", "non-canonical payment-import body")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("PayMalformed", "payment import is not a map")
        }
        guard let fmt = uintField(pairs, 1),
              let amt = uintField(pairs, 2),
              let cur = tstrField(pairs, 3),
              let payee = bstrField(pairs, 4),
              let na = uintField(pairs, 5),
              let foreign = bstrField(pairs, 6) else {
            throw NaalpError("PayMalformed", "object is not a well-formed N-AALP payment-import body")
        }
        return PaymentImport(format: fmt, amount: amt, currency: cur, payee: payee, notAfter: na, foreign: foreign)
    }

    // --- signed import (bare {1: alg} COSE_Sign1, as the reference's cose.Sign1; Ed25519 on this port) ---

    /// The bare {1: alg} COSE_Sign1 protected header (§4); `alg` is a negative int, encoded as a CBOR
    /// negative integer (major 1, argument -1 - alg).
    public static func protectedHeader(_ alg: Int) throws -> [UInt8] {
        return try Cbor.encode(.m([(.u(1), .n(UInt64(-1 - alg)))]))
    }

    /// Read the alg (label 1) value from an encoded protected header.
    public static func algFromProtected(_ prot: [UInt8]) throws -> Int {
        let v = try Cbor.decode(prot)
        guard case let .m(pairs) = v else {
            throw NaalpError("PayMalformed", "protected header is not a map")
        }
        for (k, val) in pairs {
            if case let .u(kk) = k, kk == 1 {
                if case let .n(arg) = val { return -1 - Int(arg) }
                if case let .u(u) = val { return Int(u) }
                throw NaalpError("PayMalformed", "alg is not an integer")
            }
        }
        throw NaalpError("PayMalformed", "protected header has no alg")
    }

    /// Produce the tagged COSE_Sign1 object over the PaymentImport body. PURE-ONLY Swift: the signature
    /// is a real Ed25519 (RFC 8032) signature over the ToBeSigned bytes, standing in for the reference's
    /// ML-DSA signature.
    public static func signPaymentImport(_ p: PaymentImport, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(alg)
        let payload = try p.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Verify the import's full signature under the profile, reconstruct it from the signed body bytes,
    /// and validate the format against the closed registry. Check order (fail-closed): PayMalformed ->
    /// UnknownAlg -> ProfileDowngrade -> KeyAlgMismatch -> BadSignature -> parse -> UnknownPaymentFormat.
    ///
    /// PURE-ONLY Swift: the profile floor is level 3 (ML-DSA), so a pure-Ed25519 (level-0) object is
    /// correctly floored (ProfileDowngrade); an ML-DSA object is refused at the signature step (the pure
    /// port cannot verify ML-DSA) rather than passed silently — honest F2/F4, never a faked green.
    public static func verifyPaymentImport(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> PaymentImport {
        let prot: [UInt8], payload: [UInt8], sig: [UInt8]
        do {
            (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        } catch {
            throw NaalpError("PayMalformed", "not a tagged COSE_Sign1")
        }
        let halg = try algFromProtected(prot)
        let (level, known) = Cose.algLevel(halg)
        if !known {
            throw NaalpError("UnknownAlg", "algorithm id not in the N-AALP registry")
        }
        if level < Cose.profileMinLevel(profile) {
            throw NaalpError("ProfileDowngrade", "signature level below the profile minimum")
        }
        if halg != alg {
            throw NaalpError("KeyAlgMismatch", "key algorithm does not match object header")
        }
        let tbs = try Cose.toBeSignedRaw(prot, payload)
        if !(try verifySignature(halg, pubkey, tbs, sig)) {
            throw NaalpError("BadSignature", "signature verification failed")
        }
        let p = try parsePaymentImport(payload)
        if !isRegisteredFormat(p.format) {
            throw NaalpError("UnknownPaymentFormat", "payment import selects a format outside the closed payment-format registry")
        }
        return p
    }

    /// Verify the signature over the ToBeSigned bytes. Ed25519 is verified with real crypto; ML-DSA
    /// verification is unavailable on the pure Swift port, so it is refused (fail-closed) rather than
    /// assumed valid. This branch is reachable only for a level-3+ object, which passes the floor.
    static func verifySignature(_ alg: Int, _ pubkey: [UInt8], _ tbs: [UInt8], _ sig: [UInt8]) throws -> Bool {
        if alg == Cose.ALG_ED25519 {
            return Cose.ed25519Verify(pubkey, tbs, sig)
        }
        throw NaalpError("Unavailable", "ML-DSA signature verification is unavailable on the pure Swift port")
    }

    // ---- the per-charge approval gate (reuses §7 approval + consume ledger, this wave) --------------

    /// Enforces the value-bearing rule for an imported payment, reusing the §7 approval and single-use
    /// consume ledger (Naalp.Approval) UNCHANGED. The approval MUST bind the EXACT charge binding
    /// content id (format + amount + currency + payee + expiry + foreign_id) — so it satisfies neither
    /// a different amount/payee/currency nor a substituted foreign payload (ApprovalMismatch, from
    /// Approval.verifyApproval) — its granted effect must cover the charge's CHARGE_EFFECT (a
    /// non_idempotent_write), it must be unexpired at `now`, and it is consumed single-use by `by`
    /// through the §7 ledger. Precedence and fail-closed behaviour mirror impl/go/payment.AuthorizeCharge
    /// exactly: an unregistered format denies UnknownPaymentFormat with no ledger append; a non-matching
    /// or under-granting approval denies with no ledger append; an already-spent approval denies
    /// AlreadyConsumed; the consume (the single state change) happens only when every check holds. It
    /// returns the ledger entry on success.
    public static func authorizeCharge(_ p: PaymentImport, _ appr: Approval.ApprovalRecord,
                                       _ approverVerify: Approval.Verify, _ apprSig: [UInt8], _ by: String,
                                       _ now: UInt64, _ ledger: Approval.Ledger) throws -> Approval.LedgerEntry {
        guard isRegisteredFormat(p.format) else {
            throw NaalpError("UnknownPaymentFormat", "an unknown imported format is not chargeable, fail-closed")
        }
        let chargeCID = try p.chargeBinding().contentId()
        // ApprovalMismatch (wrong amount/payee/currency/payload) / ApprovalExpired / BadSignature.
        try Approval.verifyApproval(appr, approverVerify, apprSig, chargeCID, now)
        if !Policy.authorizes(Int(appr.grant), CHARGE_EFFECT) {
            throw NaalpError("ApprovalRequired", "the approval's granted effect does not cover the charge")
        }
        // AlreadyConsumed on replay (or IO) — single-use, no double-spend.
        return try ledger.consume(try appr.id(), by)
    }
}
