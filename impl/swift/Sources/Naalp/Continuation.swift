// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C17 N-AALP-CONT flow continuation for the Swift SDK (design.md §20; R-CONT-1..7).
//
// N-AALP-CONT generalizes the C9 native-streaming pattern (one signed StreamOpen, cheap per-chunk data,
// one signed StreamCommit over a rolling digest) into a domain-agnostic *flow*:
//   - FlowOpen is the ONE full signature that fixes the flow's authority — its flow_id, its effect
//     ceiling, and the content ids of the approvals authorizing it. The authority is reconstructable
//     from the FlowOpen bytes ALONE (parseFlowOpen): no session state is needed to know what a
//     continuation is allowed to do.
//   - a Link (Continuation) is a CHEAP object: no per-object signature, only a SHA-384 hash-chain link.
//     Each link's head is SHA-384(link body); its `prev` is the previous link's head; the chain's
//     genesis prev is the FlowOpen's head, anchoring every link to THIS FlowOpen. A link carries its own
//     effect, which MUST stay at or below the ceiling (AboveCeiling otherwise — the cheap path can never
//     escalate past the one full signature + approval).
//   - Checkpoint confirms a contiguous prefix and DETECTS A GAP (GapDetected).
//   - FlowCommit is a second full signature binding the whole ordered sequence with ONE signature
//     regardless of the number of continuations (the streaming StreamCommit property).
//
// A continuation replayed under a different FlowOpen fails (WrongFlow — its flow_open_id no longer
// matches). Domain separation is structural: FlowOpen (3 fields), Link (5 fields), Checkpoint (3 fields,
// a bstr head at 3), FlowCommit (2 fields) are each a distinct deterministic-CBOR shape.
//
// An independent transcription of impl/go/continuation (cross-read against impl/python/naalp/continuation.py),
// graded against the shared vectors/continuation/cases.json. The effect lattice check reuses the shared
// Naalp.Policy.
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces — the FlowOpen/Link/Checkpoint/FlowCommit
// body/head/id, verifyChain's final head, and the AboveCeiling/GapDetected/WrongFlow/RangeError/
// CommitMismatch/NonCanonical verdicts — are pure and signature-independent. Swift cannot deterministically
// sign or verify ML-DSA (FIPS 204) with SwiftDilithium 3.6.0, so the reference's ONE-full-signature-opens/
// commits-the-flow property is demonstrated with a real Ed25519 (RFC 8032) COSE_Sign1 verified through
// Cose.coseVerify1 (which applies NO profile floor — a floored verify would reject a level-0 Ed25519
// object before the signature step). The reference's ML-DSA cross-language signed pins are NOT
// reproducible in the pure tier and are NOT fabricated here (honest F2/F4), mirroring the PHP port.

import Crypto
import Foundation

public enum Continuation {

    /// The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain.
    public static let HEAD_SIZE = 48

    /// SHA-384 over a body — a 48-octet chain head.
    static func head(_ b: [UInt8]) -> [UInt8] { return Array(SHA384.hash(data: Data(b))) }

    /// The T1 content-id framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
    static func contentID(_ b: [UInt8]) -> [UInt8] { return [0x20, 0x30] + head(b) }

    /// Whether `v` is a value of the closed C5 effect lattice (0..3). An out-of-lattice ceiling or effect
    /// is rejected RangeError, NEVER normalized to destructive: normalizing a CEILING to destructive would
    /// silently make an out-of-range ceiling the MOST-permissive one (a fail-open).
    static func inLattice(_ v: UInt64) -> Bool { return v <= UInt64(Policy.DESTRUCTIVE) }

    // ---- FlowOpen: the one full signature fixing the flow's authority (§20.2) ----------------------

    /// FlowOpen fixes a flow's identity, effect ceiling, and approval bindings.
    public struct FlowOpen {
        public let flowID: [UInt8]
        public let effectCeiling: UInt64
        public let approvals: [[UInt8]]

        public init(flowID: [UInt8], effectCeiling: UInt64, approvals: [[UInt8]]) {
            self.flowID = flowID
            self.effectCeiling = effectCeiling
            self.approvals = approvals
        }

        /// Deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(flowID)),
                (.u(2), .u(effectCeiling)),
                (.u(3), .a(approvals.map { .b($0) })),
            ]))
        }

        /// The FlowOpen's SHA-384 head — the genesis prev that anchors the continuation chain.
        public func head() throws -> [UInt8] { return Continuation.head(try bytes()) }

        /// The FlowOpen's content id — carried by every child object (Link/Checkpoint/FlowCommit).
        public func id() throws -> [UInt8] { return Continuation.contentID(try bytes()) }
    }

    /// Reconstruct a FlowOpen from its body bytes ALONE — the bearer-authority property. An out-of-lattice
    /// effect_ceiling is rejected RangeError on decode (never normalized); any malformed shape is
    /// ContMalformed. Fail-closed.
    public static func parseFlowOpen(_ b: [UInt8]) throws -> FlowOpen {
        guard let pairs = decodeMap(b),
              let fid = bstrField(pairs, 1),
              let ceil = uintField(pairs, 2),
              let appsV = arrField(pairs, 3) else {
            throw NaalpError("ContMalformed", "object is not a well-formed FlowOpen body")
        }
        if !inLattice(ceil) {
            throw NaalpError("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
        }
        var apps: [[UInt8]] = []
        apps.reserveCapacity(appsV.count)
        for e in appsV {
            guard case let .b(bs) = e else {
                throw NaalpError("ContMalformed", "approvals[] entry is not a bstr")
            }
            apps.append(bs)
        }
        return FlowOpen(flowID: fid, effectCeiling: ceil, approvals: apps)
    }

    // ---- Link: the cheap hash-chain continuation (§20.3) -------------------------------------------

    /// One cheap link in a flow's chain. NOT individually signed; its authenticity derives from the
    /// FlowOpen's signature plus the hash chain plus the FlowCommit's signature.
    public struct Link {
        public let flowOpenID: [UInt8]
        public let seq: UInt64
        public let effect: UInt64
        public let payloadID: [UInt8]
        public let prev: [UInt8]

        public init(flowOpenID: [UInt8], seq: UInt64, effect: UInt64, payloadID: [UInt8], prev: [UInt8]) {
            self.flowOpenID = flowOpenID
            self.seq = seq
            self.effect = effect
            self.payloadID = payloadID
            self.prev = prev
        }

        /// Deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(flowOpenID)),
                (.u(2), .u(seq)),
                (.u(3), .u(effect)),
                (.u(4), .b(payloadID)),
                (.u(5), .b(prev)),
            ]))
        }

        /// This link's SHA-384 head — the prev of the next link.
        public func head() throws -> [UInt8] { return Continuation.head(try bytes()) }
    }

    /// The single audited decode path for untrusted Link wire bytes. Field 3 is typed `effect` (a closed
    /// enum), so an out-of-lattice effect is rejected RangeError on decode, never carried as an unknown
    /// value into the cheap-path check. Any malformed shape is ContMalformed. Fail-closed.
    public static func parseContinuation(_ b: [UInt8]) throws -> Link {
        guard let pairs = decodeMap(b),
              let fid = bstrField(pairs, 1),
              let seq = uintField(pairs, 2),
              let effect = uintField(pairs, 3),
              let pid = bstrField(pairs, 4),
              let prev = bstrField(pairs, 5) else {
            throw NaalpError("ContMalformed", "object is not a well-formed continuation body")
        }
        if !inLattice(effect) {
            throw NaalpError("RangeError", "effect is outside the closed 0..3 lattice")
        }
        return Link(flowOpenID: fid, seq: seq, effect: effect, payloadID: pid, prev: prev)
    }

    /// The CHEAP-path check of a single link against the flow's fixed authority: the same flow
    /// (WrongFlow), the next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to
    /// the previous head (ChainBroken). No signature verification — that is what makes it cheap. An
    /// out-of-lattice ceiling or effect is RangeError (never NormalizeEffect'd — fail-closed).
    public static func verifyContinuation(_ c: Link, flowOpenID: [UInt8], prevHead: [UInt8],
                                          expectedSeq: UInt64, ceiling: UInt64) throws {
        if !inLattice(ceiling) {
            throw NaalpError("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
        }
        if !inLattice(c.effect) {
            throw NaalpError("RangeError", "continuation effect is outside the closed 0..3 lattice")
        }
        if c.flowOpenID != flowOpenID {
            throw NaalpError("WrongFlow", "object's flow_open_id does not match the FlowOpen")
        }
        if c.seq != expectedSeq {
            throw NaalpError("SeqGap", "continuation seq is not the next expected value")
        }
        if !Policy.authorizes(Int(ceiling), Int(c.effect)) {
            throw NaalpError("AboveCeiling", "continuation effect exceeds the FlowOpen effect ceiling")
        }
        if c.prev != prevHead {
            throw NaalpError("ChainBroken", "continuation prev does not chain to the previous head")
        }
    }

    /// Verify a whole ordered continuation sequence starting from the FlowOpen and return the final chain
    /// head. The ceiling comes from the FlowOpen, so the cheap path can never exceed what the single full
    /// signature authorized.
    @discardableResult
    public static func verifyChain(_ open: FlowOpen, _ conts: [Link]) throws -> [UInt8] {
        if !inLattice(open.effectCeiling) {
            throw NaalpError("RangeError", "effect_ceiling is outside the closed 0..3 lattice")
        }
        let id = try open.id()
        var prev = try open.head()
        for (i, c) in conts.enumerated() {
            try verifyContinuation(c, flowOpenID: id, prevHead: prev, expectedSeq: UInt64(i), ceiling: open.effectCeiling)
            prev = try c.head()
        }
        return prev
    }

    // ---- Checkpoint: confirm a prefix, detect a gap (§20.4) ----------------------------------------

    /// Asserts the chain head after a contiguous prefix of continuations (seq 0..throughSeq).
    public struct Checkpoint {
        public let flowOpenID: [UInt8]
        public let throughSeq: UInt64
        public let head: [UInt8]

        public init(flowOpenID: [UInt8], throughSeq: UInt64, head: [UInt8]) {
            self.flowOpenID = flowOpenID
            self.throughSeq = throughSeq
            self.head = head
        }

        /// Deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(flowOpenID)),
                (.u(2), .u(throughSeq)),
                (.u(3), .b(head)),
            ]))
        }
    }

    /// The single audited decode path for untrusted Checkpoint wire bytes (field 3 is a bstr head). It
    /// does not range-check through_seq (a full-range counter); the u64::MAX overflow guard lives in
    /// verifyCheckpoint. Any malformed shape (e.g. a 2-field FlowCommit look-alike) is ContMalformed.
    public static func parseCheckpoint(_ b: [UInt8]) throws -> Checkpoint {
        guard let pairs = decodeMap(b),
              let fid = bstrField(pairs, 1),
              let through = uintField(pairs, 2),
              let h = bstrField(pairs, 3) else {
            throw NaalpError("ContMalformed", "object is not a well-formed Checkpoint body")
        }
        return Checkpoint(flowOpenID: fid, throughSeq: through, head: h)
    }

    /// Confirm the prefix is exactly the contiguous sequence seq 0..throughSeq and that its recomputed
    /// head matches the checkpoint. A dropped or reordered link — a missing seq, a broken prev, or the
    /// wrong count — is GapDetected. A checkpoint for a different flow is WrongFlow.
    public static func verifyCheckpoint(_ cp: Checkpoint, _ open: FlowOpen, _ prefix: [Link]) throws {
        if cp.flowOpenID != (try open.id()) {
            throw NaalpError("WrongFlow", "checkpoint's flow_open_id does not match the FlowOpen")
        }
        // through_seq is a 0-based index, so the prefix length is through_seq+1. At through_seq ==
        // MaxUint64 that addition would wrap to 0 and false-accept an EMPTY prefix as covering the whole
        // counter space — reject it as a gap instead (there can be no MaxUint64+1 contiguous links).
        if cp.throughSeq == UInt64.max {
            throw NaalpError("GapDetected", "checkpoint reveals a dropped or reordered continuation")
        }
        if UInt64(prefix.count) != cp.throughSeq + 1 {
            throw NaalpError("GapDetected", "checkpoint prefix count is wrong — a link is missing or extra")
        }
        let h: [UInt8]
        do {
            h = try verifyChain(open, prefix)
        } catch {
            throw NaalpError("GapDetected", "a seq/prev break inside the prefix is a gap")
        }
        if cp.head != h {
            throw NaalpError("GapDetected", "checkpoint head does not match the recomputed prefix head")
        }
    }

    // ---- FlowCommit: the second full signature binding the whole sequence (§20.5) ------------------

    /// Binds a completed flow's final chain head under one full signature.
    public struct FlowCommit {
        public let flowOpenID: [UInt8]
        public let finalHead: [UInt8]

        public init(flowOpenID: [UInt8], finalHead: [UInt8]) {
            self.flowOpenID = flowOpenID
            self.finalHead = finalHead
        }

        /// Deterministic-CBOR encoding {1: flow_open_id, 2: final_head} — the 2-field shape that
        /// distinguishes it from the 3-field Checkpoint.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(flowOpenID)),
                (.u(2), .b(finalHead)),
            ]))
        }
    }

    // ---- full-signature demonstrations (Ed25519, isolation — NOT corpus-graded) --------------------

    /// The bare {1: alg} COSE_Sign1 protected header (alg is a negative int).
    static func protectedHeader(_ alg: Int) throws -> [UInt8] {
        return try Cbor.encode(.m([(.u(1), .n(UInt64(-1 - alg)))]))
    }

    /// Produce the tagged COSE_Sign1 object over the FlowOpen body (the one full signature that opens the
    /// flow). PURE-ONLY Swift: a real Ed25519 (RFC 8032) signature stands in for the reference's ML-DSA.
    public static func signFlowOpen(_ o: FlowOpen, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(Cose.ALG_ED25519)
        let payload = try o.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Verify the FlowOpen's full signature (Ed25519, no profile floor) and reconstruct the authority from
    /// the signed body bytes. A bad signature is BadSignature (fail-closed).
    public static func verifyFlowOpen(_ obj: [UInt8], _ pk: [UInt8]) throws -> FlowOpen {
        if !(try Cose.coseVerify1(Cose.ALG_ED25519, pk, obj)) {
            throw NaalpError("BadSignature", "flow-open signature does not verify")
        }
        let (_, payload, _) = try Cose.parseSign1Raw(obj)
        return try parseFlowOpen(payload)
    }

    /// Produce the tagged COSE_Sign1 object over the FlowCommit body.
    public static func signFlowCommit(_ c: FlowCommit, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(Cose.ALG_ED25519)
        let payload = try c.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Verify the FlowCommit's full signature (Ed25519, no floor), that it binds this FlowOpen (WrongFlow),
    /// and that its final_head equals the chain recomputed over the delivered continuations (CommitMismatch,
    /// or the chain error). A missing or reordered continuation makes the recomputed head differ.
    @discardableResult
    public static func verifyFlowCommit(_ obj: [UInt8], _ pk: [UInt8], _ open: FlowOpen, _ conts: [Link]) throws -> FlowCommit {
        if !(try Cose.coseVerify1(Cose.ALG_ED25519, pk, obj)) {
            throw NaalpError("BadSignature", "flow-commit signature does not verify")
        }
        let (_, payload, _) = try Cose.parseSign1Raw(obj)
        guard let pairs = decodeMap(payload),
              let fid = bstrField(pairs, 1),
              let fh = bstrField(pairs, 2) else {
            throw NaalpError("ContMalformed", "object is not a well-formed FlowCommit body")
        }
        let fc = FlowCommit(flowOpenID: fid, finalHead: fh)
        if fc.flowOpenID != (try open.id()) {
            throw NaalpError("WrongFlow", "flow commit does not bind this FlowOpen")
        }
        let finalHead = try verifyChain(open, conts)
        if fc.finalHead != finalHead {
            throw NaalpError("CommitMismatch", "flow commit final_head does not match the recomputed chain")
        }
        return fc
    }

    // ---- small deterministic-CBOR field accessors --------------------------------------------------

    static func decodeMap(_ b: [UInt8]) -> [(CborValue, CborValue)]? {
        guard let v = try? Cbor.decode(b), case let .m(pairs) = v else { return nil }
        return pairs
    }

    static func field(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> CborValue? {
        for (key, val) in pairs {
            if case let .u(kk) = key, kk == k { return val }
        }
        return nil
    }

    static func bstrField(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> [UInt8]? {
        if case let .b(x)? = field(pairs, k) { return x }
        return nil
    }

    static func uintField(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> UInt64? {
        if case let .u(x)? = field(pairs, k) { return x }
        return nil
    }

    static func arrField(_ pairs: [(CborValue, CborValue)], _ k: UInt64) -> [CborValue]? {
        if case let .a(x)? = field(pairs, k) { return x }
        return nil
    }
}
