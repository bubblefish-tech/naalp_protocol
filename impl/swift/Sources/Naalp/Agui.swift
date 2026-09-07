// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C21 NAALP-AGUI UI-consent binding for the Swift SDK (design.md §24; R-AGUI-1..6).
//
// NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
// tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
// RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
// envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary
// signed N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction
// (§8.1) unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior
// head carried in `prev` so editing or omitting an event breaks the next event's linkage — and the §7
// approval binding (Naalp.Approval) UNCHANGED.
//
//   - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
//     `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id
//     of the action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.
//
// The load-bearing properties, graded against the shared corpus:
//   - A UI approval verifies ONLY against the EXACT action shown. verifyConsent walks the shown chain,
//     takes the action content id from the shown-and-approved event, and requires the action actually
//     being executed to hash to THAT content id (ActionSubstituted otherwise) AND the human §7 approval
//     to bind it (ApprovalMismatch otherwise). A substituted action has a different content id.
//   - A removed/omitted shown-event is detected with its POSITION. walkShown enforces contiguity and
//     raises UIChainBroken on a gap; detectHole reports the first-broken position.
//
// An independent transcription of impl/go/agui (cross-read against impl/python/naalp/agui.py), graded
// against the shared vectors/agui/cases.json. The kind vocabulary, event bodies/heads/ids, action
// content ids, the shown-chain walk, the hole position, and the wire-format rejections are
// signature-independent and pure.
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces are pure. Swift cannot deterministically sign or
// verify ML-DSA (FIPS 204) with SwiftDilithium 3.6.0, so the UI-event signature the reference makes
// with ML-DSA-65 is demonstrated with a real Ed25519 (RFC 8032) signature — signUIEvent signs the event
// body directly, and verifyShownChain / verifyConsent take an injected `(msg, sig) -> Bool` verifier (as
// Approval and Audit do). agui carries NO consume ledger: it reuses the §7 approval BINDING
// (Approval.verifyApproval) only; the single-use consume loop is demonstrated through Mcp.authorizeCall
// (honest F2/F4, mirroring the PHP/C# ports). The reference's ML-DSA cross-language signed pins are NOT
// reproducible here and are NOT fabricated.
//
// Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
// causes no state change.

import Crypto
import Foundation

public enum Agui {

    /// The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. Genesis
    /// is zero.
    public static let HEAD_SIZE = 48

    // UI event kinds — the closed AG-UI tool-lifecycle set. A kind outside the set is rejected.
    public static let KIND_SHOWN: UInt64 = 0      // the action / tool call was shown (rendered) to the user
    public static let KIND_ARGS_SHOWN: UInt64 = 1 // the arguments were shown to the user
    public static let KIND_APPROVED: UInt64 = 2   // the user approved the shown action
    public static let KIND_REJECTED: UInt64 = 3   // the user rejected the shown action

    /// A `(msg, sig) -> Bool` signature verifier the pure-tier signature gates take by injection
    /// (Ed25519 on this pure port; the reference resolves an ML-DSA verifier for the UI authority).
    public typealias Verify = (_ msg: [UInt8], _ sig: [UInt8]) -> Bool

    static let kindNames: [UInt64: String] = [
        KIND_SHOWN: "shown", KIND_ARGS_SHOWN: "args-shown", KIND_APPROVED: "approved", KIND_REJECTED: "rejected",
    ]

    /// Whether `code` is one of the closed UI-event kinds.
    public static func isKnownKind(_ code: UInt64) -> Bool { return kindNames[code] != nil }

    /// The kind name, or "unknown".
    public static func kindName(_ code: UInt64) -> String { return kindNames[code] ?? "unknown" }

    /// A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).
    public static func genesis() -> [UInt8] { return [UInt8](repeating: 0, count: HEAD_SIZE) }

    /// The T1 content id of arbitrary bytes — the content id of an ACTION a UI event names in field 3
    /// and a human approval binds: multihash(0x20, SHA-384(body)).
    public static func contentId(_ b: [UInt8]) -> [UInt8] { return Cbor.contentId(b) }

    static func head(_ b: [UInt8]) -> [UInt8] { return Array(SHA384.hash(data: Data(b))) }

    // ---- UIEvent: one receipt-chained shown tool-lifecycle event (§24) -----------------------------

    /// One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event:
    /// `prev` is the prior event's head (genesis for seq 0). `action` is the content id of the exact
    /// action bytes shown to the user at this step.
    public struct UIEvent {
        public let session: [UInt8] // UI session id (ties the stream together)
        public let kind: UInt64     // the event kind (closed set)
        public let action: [UInt8]  // content id of the exact action bytes shown at this step
        public let seq: UInt64      // monotonic per-session chain position; seq 0 is the genesis event
        public let prev: [UInt8]    // the prior event's head (HEAD_SIZE bytes; genesis is zero)

        public init(session: [UInt8], kind: UInt64, action: [UInt8], seq: UInt64, prev: [UInt8]) {
            self.session = session
            self.kind = kind
            self.action = action
            self.seq = seq
            self.prev = prev
        }

        /// Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(session)),
                (.u(2), .u(kind)),
                (.u(3), .b(action)),
                (.u(4), .u(seq)),
                (.u(5), .b(prev)),
            ]))
        }

        /// The chain head after this event: SHA-384 of the event body (48 octets). Because the body
        /// carries prev, editing any event breaks the next event's linkage.
        public func head() throws -> [UInt8] { return Agui.head(try bytes()) }

        /// The event's T1 content id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }
    }

    /// Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint key,
    /// a mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed.
    public static func parseUIEvent(_ b: [UInt8]) throws -> UIEvent {
        let v: CborValue
        do {
            v = try Cbor.decode(b)
        } catch {
            throw NaalpError("UIMalformed", "ui-event body is not well-formed deterministic CBOR")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("UIMalformed", "ui-event body is not a map")
        }
        var session: [UInt8]? = nil, kind: UInt64? = nil, action: [UInt8]? = nil
        var seq: UInt64? = nil, prev: [UInt8]? = nil
        for (k, val) in pairs {
            guard case let .u(key) = k else {
                throw NaalpError("UIMalformed", "non-uint ui-event key")
            }
            switch key {
            case 1:
                guard case let .b(bs) = val else { throw NaalpError("UIMalformed", "session not bstr") }
                session = bs
            case 2:
                guard case let .u(u) = val else { throw NaalpError("UIMalformed", "kind not uint") }
                kind = u
            case 3:
                guard case let .b(bs) = val else { throw NaalpError("UIMalformed", "action not bstr") }
                action = bs
            case 4:
                guard case let .u(u) = val else { throw NaalpError("UIMalformed", "seq not uint") }
                seq = u
            case 5:
                guard case let .b(bs) = val else { throw NaalpError("UIMalformed", "prev not bstr") }
                prev = bs
            default:
                throw NaalpError("UIMalformed", "unknown ui-event field \(key)")
            }
        }
        guard let s = session, let k = kind, let a = action, let sq = seq, let p = prev else {
            throw NaalpError("UIMalformed", "ui-event body missing a mandatory field")
        }
        return UIEvent(session: s, kind: k, action: a, seq: sq, prev: p)
    }

    /// Sign a UI event with a real deterministic Ed25519 key derived from a 32-byte seed (the pure-tier
    /// stand-in for the reference's ML-DSA-65 signer). The signed input is the event body bytes DIRECTLY.
    public static func signUIEvent(_ e: UIEvent, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try e.bytes())
    }

    // ---- verifyUIEvent: full COSE_Sign1 verification under the profile (parity with impl/go) --------
    //
    // `signUIEvent` above signs the event body bytes DIRECTLY (a raw Ed25519 signature demonstration
    // consumed by the receipt-chain walk, verifyShownChain/verifyConsent). impl/go's
    // SignUIEvent/VerifyUIEvent instead operate on the object as a full tagged COSE_Sign1
    // (cose.Sign1/cose.Verify1, §4); this pair mirrors that wire shape — exactly as
    // Payment.signPaymentImport/verifyPaymentImport already do for the sibling C21 surface — so a
    // profile-gated COSE_Sign1 UI event can be produced and verified end-to-end.

    /// The bare {1: alg} COSE_Sign1 protected header (§4); `alg` is a negative int, encoded as a CBOR
    /// negative integer (major 1, argument -1 - alg).
    static func protectedHeader(_ alg: Int) throws -> [UInt8] {
        return try Cbor.encode(.m([(.u(1), .n(UInt64(-1 - alg)))]))
    }

    /// Read the alg (label 1) value from an encoded protected header.
    static func algFromProtected(_ prot: [UInt8]) throws -> Int {
        let v = try Cbor.decode(prot)
        guard case let .m(pairs) = v else {
            throw NaalpError("UIMalformed", "protected header is not a map")
        }
        for (k, val) in pairs {
            if case let .u(kk) = k, kk == 1 {
                if case let .n(arg) = val { return -1 - Int(arg) }
                if case let .u(u) = val { return Int(u) }
                throw NaalpError("UIMalformed", "alg is not an integer")
            }
        }
        throw NaalpError("UIMalformed", "protected header has no alg")
    }

    /// Produce the tagged COSE_Sign1 object over the UIEvent body. PURE-ONLY Swift: the signature is a
    /// real Ed25519 (RFC 8032) signature over the ToBeSigned bytes, standing in for the reference's
    /// ML-DSA-65 signer (as `signPaymentImport` does). Distinct from `signUIEvent`, which signs the
    /// body bytes directly for the receipt-chain walk; this produces the full wire object
    /// `verifyUIEvent` (and impl/go's `SignUIEvent`/`VerifyUIEvent`) operate on.
    public static func signUIEventObject(_ e: UIEvent, _ alg: Int, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(alg)
        let payload = try e.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Verify the event's full signature under the profile, reconstruct it from the signed body bytes,
    /// and validate the kind against the closed set (UnknownUIEventKind). A bad signature propagates as
    /// BadSignature. Fail-closed. Mirrors impl/go/agui.VerifyUIEvent(obj, profile, v) exactly: check
    /// order is UIMalformed (not a tagged COSE_Sign1) -> UnknownAlg -> ProfileDowngrade ->
    /// KeyAlgMismatch -> BadSignature -> parse -> UnknownUIEventKind.
    ///
    /// PURE-ONLY Swift: the profile floor is level 3 (ML-DSA), so a pure-Ed25519 (level-0) object is
    /// correctly floored (ProfileDowngrade); an ML-DSA object is refused at the signature step (the
    /// pure port cannot verify ML-DSA) rather than passed silently — honest F2/F4, mirroring
    /// Payment.verifyPaymentImport. Because the floor always rejects a pure-Ed25519 object here, the
    /// KeyAlgMismatch/BadSignature/UnknownUIEventKind branches below are exercised in isolation via the
    /// raw Cose.coseVerify1 round-trip in AguiTests, not by a call reaching them through this function
    /// (the same honest limitation Payment.verifyPaymentImport already documents).
    public static func verifyUIEvent(_ obj: [UInt8], _ profile: Int, _ alg: Int, _ pubkey: [UInt8]) throws -> UIEvent {
        let prot: [UInt8], payload: [UInt8], sig: [UInt8]
        do {
            (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        } catch {
            throw NaalpError("UIMalformed", "not a tagged COSE_Sign1")
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
        if halg == Cose.ALG_ED25519 {
            if !Cose.ed25519Verify(pubkey, tbs, sig) {
                throw NaalpError("BadSignature", "signature verification failed")
            }
        } else {
            throw NaalpError("Unavailable", "ML-DSA signature verification is unavailable on the pure Swift port")
        }
        let e = try parseUIEvent(payload)
        if !isKnownKind(e.kind) {
            throw NaalpError("UnknownUIEventKind", "ui-event kind is outside the closed set")
        }
        return e
    }

    // ---- the shown chain: contiguity, walk, hole detection (mirrors the C7 chain) ------------------

    /// One step of a walked shown chain: the chain position, the event kind, the action content id
    /// shown, and the chain head after it.
    public struct ShownEvent {
        public let seq: UInt64
        public let kind: UInt64
        public let action: [UInt8]
        public let head: [UInt8]

        public init(seq: UInt64, kind: UInt64, action: [UInt8], head: [UInt8]) {
            self.seq = seq
            self.kind = kind
            self.action = action
            self.head = head
        }
    }

    /// Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered
    /// shown events. Requires every event to name the SAME session, seq i to equal its index, each kind
    /// to be in the closed set, and prev to link to the previous event's head (genesis for seq 0). A gap,
    /// reorder, omitted event, or a session change is UIChainBroken; an unknown kind is
    /// UnknownUIEventKind. Fail-closed.
    public static func walkShown(_ events: [UIEvent]) throws -> [ShownEvent] {
        var out: [ShownEvent] = []
        var h = genesis()
        var session: [UInt8]? = nil
        for (i, e) in events.enumerated() {
            if i == 0 {
                session = e.session
            } else if e.session != session {
                throw NaalpError("UIChainBroken", "a chain is for exactly one session")
            }
            if !isKnownKind(e.kind) {
                throw NaalpError("UnknownUIEventKind", "ui-event kind is outside the closed set")
            }
            if e.seq != UInt64(i) || e.prev != h {
                throw NaalpError("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
            }
            h = try e.head()
            out.append(ShownEvent(seq: e.seq, kind: e.kind, action: e.action, head: h))
        }
        return out
    }

    /// Verify a UI event chain offline against the UI authority's key: each event's signature
    /// (Ed25519-demonstrated, via the injected `verify` closure over the event body bytes) AND the same
    /// structural continuity as walkShown. A bad/foreign signature is BadSignature; a broken link, seq
    /// gap, session change, or unknown kind is UIChainBroken / UnknownUIEventKind. Detects any reorder,
    /// omission, or substitution of a shown event (§8.1). Fail-closed. `sigs` is parallel to `events`.
    public static func verifyShownChain(_ events: [UIEvent], _ sigs: [[UInt8]], _ verify: Verify) throws -> [UIEvent] {
        var h = genesis()
        var session: [UInt8]? = nil
        var out: [UIEvent] = []
        for (i, e) in events.enumerated() {
            let body = try e.bytes()
            if i >= sigs.count || !verify(body, sigs[i]) {
                throw NaalpError("BadSignature", "ui-event signature does not verify")
            }
            if !isKnownKind(e.kind) {
                throw NaalpError("UnknownUIEventKind", "ui-event kind is outside the closed set")
            }
            if i == 0 {
                session = e.session
            } else if e.session != session {
                throw NaalpError("UIChainBroken", "a chain is for exactly one session")
            }
            if e.seq != UInt64(i) || e.prev != h {
                throw NaalpError("UIChainBroken", "ui-event prev/seq does not chain to the previous event")
            }
            h = try e.head()
            out.append(e)
        }
        return out
    }

    /// Report whether a presented (possibly gappy) event list breaks contiguity — a deleted/omitted
    /// shown-event — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's
    /// seq is not i or its prev does not link to the previous event's head. A contiguous list returns
    /// (0, false).
    public static func detectHole(_ events: [UIEvent]) throws -> (position: Int, hole: Bool) {
        var h = genesis()
        for (i, e) in events.enumerated() {
            if e.seq != UInt64(i) || e.prev != h {
                return (i, true)
            }
            h = try e.head()
        }
        return (0, false)
    }

    // ---- the UI consent binding (reuses the §7 approval) ------------------------------------------

    /// The content id of the action shown-and-approved in a walked chain, and whether an approved event
    /// is present. It is the content id a valid consent binds; a chain with no approved event has no
    /// consent to bind.
    public static func approvedActionCid(_ shown: [ShownEvent]) -> (cid: [UInt8]?, ok: Bool) {
        for ev in shown where ev.kind == KIND_APPROVED {
            return (ev.action, true)
        }
        return (nil, false)
    }

    /// Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks the
    /// shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content id
    /// from the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7
    /// approval binds THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired /
    /// BadSignature, from Approval); and (4) requires the action actually being executed (`actionBytes`)
    /// to hash to the shown-and-approved content id — a SUBSTITUTED action has a different content id and
    /// is rejected (ActionSubstituted). Every failure returns its named error and authorizes nothing
    /// (fail-closed). On success the caller may execute exactly `actionBytes`.
    ///
    /// `approverVerify` is `(msg, sig) -> Bool` — the injected human-approval signature verifier
    /// (Ed25519 on the pure port). agui carries NO consume ledger: this is the §7 approval BINDING only.
    public static func verifyConsent(_ chain: [UIEvent], _ actionBytes: [UInt8], _ appr: Approval.ApprovalRecord,
                                     _ approverVerify: Approval.Verify, _ apprSig: [UInt8], _ now: UInt64) throws {
        let shown = try walkShown(chain) // UIChainBroken / UnknownUIEventKind on a hole
        let (shownCID, ok) = approvedActionCid(shown)
        guard ok, let cid = shownCID else {
            throw NaalpError("UINoConsent", "the shown chain carries no approved event — there is no human consent to bind")
        }
        // The human approval must be a valid signature binding the shown-and-approved action content id.
        try Approval.verifyApproval(appr, approverVerify, apprSig, cid, now) // BadSignature / ApprovalMismatch / ApprovalExpired
        // The action actually being executed MUST be the exact one shown and approved: a substitution has
        // a different content id and is rejected. This is the seam a lax UI profile would drop.
        if contentId(actionBytes) != cid {
            throw NaalpError("ActionSubstituted", "the action being executed is not the exact action shown and approved in the UI stream")
        }
    }
}
