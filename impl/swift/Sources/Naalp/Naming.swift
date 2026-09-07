// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C19 — name bindings and the signed A2A task-state profile for the Swift SDK (design.md §22;
// R-NAME-1..6, R-A2A-1..7).
//
// C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own signed object.
// Both reuse the C7 audit receipt-chain construction (§8.1) unchanged — head = SHA-384(body), genesis
// prev = 48 zero bytes, a monotonic seq, the prior head carried in the body so editing or omitting a
// record breaks the next record's linkage — and they add NO new envelope, encoding, signature,
// identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP body (COSE_Sign1),
// reusing the T1 content-id framing (§2.3) and the C7 chain.
//
// Task 4.1 — name bindings: NameBinding {1:name,2:signer,3:seq,4:prev} maps a name to a signer id and
// CHAINS onto the prior binding for that name (prev = the prior binding's head; genesis prev is zero). A
// key rotation is a NEW binding at the next seq naming the new signer. The binding is DATED BY its chain
// position (seq); the envelope's `created` field is advisory only. A name's history is WALKABLE offline
// (walkHistory), a deleted/omitted binding leaves a detectable HOLE at the first-broken position
// (detectHole), and two bindings by ONE authority at the SAME (name, seq) naming DIFFERENT signers are a
// FORK reported at that seq (detectFork / NameForkProof).
//
// Task 4.2 — the signed A2A task-state profile: the eight imported A2A (Agent2Agent) TaskState values
// (carriage, not adoption): submitted, working, input-required, auth-required, completed, canceled,
// failed, rejected (A2A §4.1.3: start = submitted; terminal = completed/canceled/failed/rejected;
// interrupted = input-required/auth-required). A Transition {1:task,2:card,3:from,4:to,5:seq,6:prev} is
// one receipt-CHAINED signed state transition. The legal-edge table is DERIVED from those documented
// A2A category rules; verifyTransition rejects an illegal edge, and the task-chain walk enforces the
// start state, contiguity, the legal-edge table, prev/seq linkage, and the card binding. `card` is the
// content-id of the A2A Agent Card attestation (a C18 naalp-description-import) that binds the profile
// to an agent/operation; a transition carrying a foreign card is rejected.
//
// An independent transcription of impl/go/naming (cross-read against impl/python/naalp/naming.py and
// impl/php/src/Naming.php), graded against the shared vectors/naming/cases.json. Every check is
// fail-closed (§15): a failing object is rejected whole, returns its named error, and causes no state
// change.
//
// CRYPTO SCOPE (PURE-ONLY, honest F2/F4): C19's cross-language SIGNED pins are real deterministic ML-DSA
// (FIPS 204) COSE_Sign1 objects (a seq-0 binding and a seq-0 transition). Swift has no
// deterministic-from-seed ML-DSA signer (SwiftDilithium 3.6.0), so those signed pins are NOT
// reproducible here and are NOT faked. Every surface this port grades against the corpus — the
// NameBinding/Transition bodies/heads/ids, the walk/hole/fork/gap positions, the A2A legal/illegal edge
// table, the strict-decoder NonCanonical rejection, the look-alike NameMalformed rejections, and the
// Agent-Card import content-id — is signature-independent and pure. The signature BINDING
// (signBinding/verifyChain, NameForkProof, signTransition/verifyTaskChain) is demonstrated in isolation
// with a real Ed25519 (RFC 8032) round-trip via swift-crypto; the injected verify closure is the
// pure-tier stand-in for the reference's ML-DSA verifier. BadSignature/NonCanonical are the same kinds
// the reference carries.

import Crypto
import Foundation

public enum Naming {
    /// The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain.
    public static let HEAD_SIZE = 48

    /// A `(msg, sig) -> Bool` signature verifier the signed paths take by injection (Ed25519 on this
    /// pure Swift port; the reference resolves an ML-DSA verifier for the signer).
    public typealias Verify = (_ msg: [UInt8], _ sig: [UInt8]) -> Bool

    // A2A TaskState codes (stable N-AALP wire codes for the imported A2A vocabulary; A2A §4.1.3).
    public static let STATE_SUBMITTED: UInt64 = 0      // acknowledged, not yet started (the start state)
    public static let STATE_WORKING: UInt64 = 1        // actively processed
    public static let STATE_INPUT_REQUIRED: UInt64 = 2 // interrupted, awaiting client input
    public static let STATE_AUTH_REQUIRED: UInt64 = 3  // interrupted, awaiting authentication
    public static let STATE_COMPLETED: UInt64 = 4      // terminal success
    public static let STATE_CANCELED: UInt64 = 5       // terminal, canceled before completion
    public static let STATE_FAILED: UInt64 = 6         // terminal, finished with an error
    public static let STATE_REJECTED: UInt64 = 7       // terminal, the agent declined the task
    public static let START_STATE: UInt64 = 0

    static let stateNames: [UInt64: String] = [
        0: "submitted", 1: "working", 2: "input-required", 3: "auth-required",
        4: "completed", 5: "canceled", 6: "failed", 7: "rejected",
    ]

    /// A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).
    public static func genesis() -> [UInt8] {
        return [UInt8](repeating: 0, count: HEAD_SIZE)
    }

    // ==== Task 4.1 — name bindings ================================================================

    /// Maps a name to a signer id at a chain position. It chains onto the prior binding for the same
    /// name: prev is the prior binding's head (genesis for seq 0). A key rotation is a new binding at the
    /// next seq naming the new signer. Dated by seq; the envelope's `created` is advisory.
    public struct NameBinding {
        public let name: String   // the name being bound (a durable, human-readable name)
        public let signer: [UInt8] // the signer id this binding maps the name to (opaque bytes; §5.1)
        public let seq: UInt64    // monotonic per-name chain position; seq 0 is the genesis binding
        public let prev: [UInt8]  // the prior binding's head (HEAD_SIZE bytes; genesis is zero)

        public init(name: String, signer: [UInt8], seq: UInt64, prev: [UInt8]) {
            self.name = name
            self.signer = signer
            self.seq = seq
            self.prev = prev
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .t(name)),
                (.u(2), .b(signer)),
                (.u(3), .u(seq)),
                (.u(4), .b(prev)),
            ])
        }

        /// Deterministic-CBOR encoding {1:name,2:signer,3:seq,4:prev}.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }

        /// The chain head after this binding: SHA-384 of the binding body (48 octets).
        public func head() throws -> [UInt8] { return Array(SHA384.hash(data: Data(try bytes()))) }

        /// The binding's T1 content-id (50 octets): multihash(0x20, SHA-384(body)).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }
    }

    /// One step of a walked name history: the chain position and the signer the name mapped to at that
    /// position, with the chain head after it.
    public struct NameEvent {
        public let seq: UInt64
        public let signer: [UInt8]
        public let head: [UInt8]
        public init(seq: UInt64, signer: [UInt8], head: [UInt8]) {
            self.seq = seq
            self.signer = signer
            self.head = head
        }
    }

    /// A naming authority that appends monotonic signed bindings for ONE name (mirroring the C7 audit
    /// authority). Each append records a name -> signer mapping at the next chain position; a rotation is
    /// simply an append naming the new signer. Signs with a real Ed25519 (RFC 8032) key from `seed` (the
    /// pure-tier stand-in for the reference's deterministic ML-DSA signer).
    public final class Registrar {
        private let name: String
        private let seed: [UInt8]
        private var chainHead: [UInt8]
        private var seq: UInt64

        public init(name: String, seed: [UInt8]) {
            self.name = name
            self.seed = seed
            self.chainHead = Naming.genesis()
            self.seq = 0
        }

        /// Record a binding of the registrar's name to `subject` at the next chain position, returning
        /// (binding, tagged COSE_Sign1 object). Seq increases by one per append (monotonic); the chain
        /// head advances to the new binding's head.
        public func append(_ subject: [UInt8]) throws -> (binding: NameBinding, obj: [UInt8]) {
            let nb = NameBinding(name: name, signer: subject, seq: seq, prev: chainHead)
            let obj = try Naming.signBinding(nb, seed)
            chainHead = try nb.head()
            seq += 1
            return (nb, obj)
        }
    }

    /// Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the {1,2,3,4} map
    /// with the right value types (or is non-canonical) is NameMalformed (fail-closed).
    public static func parseNameBinding(_ b: [UInt8]) throws -> NameBinding {
        guard let m = decodeMap(b) else {
            throw NaalpError("NameMalformed", "body is not a well-formed name binding")
        }
        guard let name = tstrField(m, 1), let signer = bstrField(m, 2),
              let seq = uintField(m, 3), let prev = bstrField(m, 4) else {
            throw NaalpError("NameMalformed", "body is not a well-formed name binding")
        }
        return NameBinding(name: name, signer: signer, seq: seq, prev: prev)
    }

    /// Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return the ordered
    /// signer succession. Requires every binding to name the SAME name, seq i to equal its index, and
    /// prev to link to the previous binding's head (genesis zero for seq 0). A gap, reorder, omitted
    /// binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer is the last event's
    /// signer.
    public static func walkHistory(_ bindings: [NameBinding]) throws -> [NameEvent] {
        var events: [NameEvent] = []
        var h = genesis()
        var name: String? = nil
        for (i, nb) in bindings.enumerated() {
            if i == 0 {
                name = nb.name
            } else if nb.name != name {
                throw NaalpError("NameChainBroken", "a chain is for exactly one name")
            }
            if nb.seq != UInt64(i) || nb.prev != h {
                throw NaalpError("NameChainBroken", "prev/seq does not chain to the previous binding")
            }
            h = try nb.head()
            events.append(NameEvent(seq: nb.seq, signer: nb.signer, head: h))
        }
        return events
    }

    /// Report whether a presented (possibly gappy) binding list breaks contiguity — a deleted/omitted
    /// binding — and, if so, the FIRST-BROKEN position: the index i where the i-th presented binding's
    /// seq is not i or its prev does not link to the previous binding's head. A contiguous list returns
    /// (0, false).
    public static func detectHole(_ bindings: [NameBinding]) -> (position: Int, hole: Bool) {
        var h = genesis()
        for (i, nb) in bindings.enumerated() {
            if nb.seq != UInt64(i) || nb.prev != h {
                return (i, true)
            }
            h = (try? nb.head()) ?? h
        }
        return (0, false)
    }

    /// Compare two bindings for the SAME name and report whether they equivocate — the SAME name and seq
    /// but DIFFERENT bodies — and, if so, the seq position. A different name or seq is a legitimate
    /// distinct binding; byte-identical bindings are a benign duplicate. Both non-fork cases return
    /// (0, false).
    public static func detectFork(_ a: NameBinding, _ b: NameBinding) -> (position: Int, fork: Bool) {
        if a.name != b.name || a.seq != b.seq {
            return (0, false)
        }
        if let ab = try? a.bytes(), let bb = try? b.bytes(), ab == bb {
            return (0, false)
        }
        return (Int(a.seq), true)
    }

    /// The bare {1: nint(alg)} COSE_Sign1 protected header (as the reference cose.Sign1 emits). A
    /// negative-int CBOR head carries `arg` where the logical value is `-1 - arg`, so `arg = -1 - alg`.
    static func protectedHeader(_ alg: Int) throws -> [UInt8] {
        return try Cbor.encode(.m([(.u(1), .n(UInt64(-1 - alg)))]))
    }

    /// Produce the tagged COSE_Sign1 object over the binding body with a real Ed25519 (RFC 8032)
    /// signature (the pure-tier stand-in for the reference's deterministic ML-DSA signer).
    public static func signBinding(_ nb: NameBinding, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(Cose.ALG_ED25519)
        let payload = try nb.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Verify a signed binding's signature via the injected verifier, then reconstruct it from the signed
    /// body bytes. A bad signature is BadSignature; a malformed body is NameMalformed. `verify` is
    /// `(msg, sig) -> Bool` (Ed25519 on the pure Swift port).
    public static func verifyBinding(_ obj: [UInt8], _ verify: Verify) throws -> NameBinding {
        let (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        if !verify(try Cose.toBeSignedRaw(prot, payload), sig) {
            throw NaalpError("BadSignature", "signature does not verify")
        }
        return try parseNameBinding(payload)
    }

    /// Check a name-binding chain offline against the authority's key. Each element is the tagged
    /// COSE_Sign1 object for one binding. Verifies every signature (verifyBinding), then enforces
    /// structural continuity (walkHistory) — same name, seq i == index, prev links to the previous head —
    /// returning the verified, ordered bindings. A bad signature is BadSignature; a broken link, a seq
    /// gap, or a name change is NameChainBroken. Fail-closed.
    public static func verifyChain(_ objs: [[UInt8]], _ verify: Verify) throws -> [NameBinding] {
        var bindings: [NameBinding] = []
        for obj in objs {
            bindings.append(try verifyBinding(obj, verify))
        }
        _ = try walkHistory(bindings) // structural continuity (throws NameChainBroken)
        return bindings
    }

    /// Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE authority at
    /// the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's OWN two signed
    /// objects (the tagged COSE_Sign1 bytes). Because a single verifier checks BOTH signed objects, the
    /// proof is self-contained.
    public struct NameForkProof {
        public let signer: [UInt8]  // accused authority signer id (both objects verify under its key)
        public let signedA: [UInt8]
        public let signedB: [UInt8]

        public init(signer: [UInt8], signedA: [UInt8], signedB: [UInt8]) {
            self.signer = signer
            self.signedA = signedA
            self.signedB = signedB
        }

        /// Accept iff ALL hold: (1) the signer id is present; (2) BOTH signed objects verify under the
        /// injected verifier (which, because one verifier checks both, proves one authority); (3) the two
        /// bindings share one name and seq; and (4) their bodies differ. Returns the seq position at which
        /// it forks. An unnamed signer, a different name/seq, or identical bodies is NameForkProofInvalid;
        /// a signature that does not verify is BadSignature. Fail-closed. `verify` is `(msg, sig) -> Bool`.
        public func verify(_ verify: Verify) throws -> Int {
            if signer.isEmpty {
                throw NaalpError("NameForkProofInvalid", "an unnamed accused is not evidence")
            }
            let a = try Naming.verifyBinding(signedA, verify)
            let b = try Naming.verifyBinding(signedB, verify)
            let (pos, fork) = Naming.detectFork(a, b)
            if !fork {
                throw NaalpError("NameForkProofInvalid", "not the same (name, seq) or identical bodies")
            }
            return pos
        }
    }

    // ==== Task 4.2 — the signed A2A task-state profile ============================================

    /// The A2A state name for a code, or "unknown".
    public static func stateName(_ s: UInt64) -> String { return stateNames[s] ?? "unknown" }

    /// Whether s is one of the eight defined A2A states.
    public static func isState(_ s: UInt64) -> Bool { return stateNames[s] != nil }

    /// Whether s is a terminal state (completed/canceled/failed/rejected).
    public static func isTerminal(_ s: UInt64) -> Bool {
        return s == STATE_COMPLETED || s == STATE_CANCELED || s == STATE_FAILED || s == STATE_REJECTED
    }

    /// Whether s is an interrupted state (input-required/auth-required).
    public static func isInterrupted(_ s: UInt64) -> Bool {
        return s == STATE_INPUT_REQUIRED || s == STATE_AUTH_REQUIRED
    }

    /// The A2A legal transition table, derived from the documented category rules (design §22.3),
    /// computed once. Each edge is [from, to].
    static let legalEdgeSet: Set<[UInt64]> = {
        let active: [UInt64] = [STATE_SUBMITTED, STATE_WORKING]
        let interrupted: [UInt64] = [STATE_INPUT_REQUIRED, STATE_AUTH_REQUIRED]
        let terminal: [UInt64] = [STATE_COMPLETED, STATE_CANCELED, STATE_FAILED, STATE_REJECTED]
        var s = Set<[UInt64]>()
        s.insert([STATE_SUBMITTED, STATE_WORKING]) // begin processing (the only active->active edge)
        for f in active { for t in interrupted { s.insert([f, t]) } } // active -> interrupted
        for f in active { for t in terminal { s.insert([f, t]) } }    // active -> terminal
        for f in interrupted { s.insert([f, STATE_WORKING]) }         // interrupted -> working (client acted)
        for f in interrupted { for t in terminal { s.insert([f, t]) } } // interrupted -> terminal
        return s
    }()

    /// Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an edge out of a
    /// terminal state, an edge touching an undefined state, and any edge not in the table are all false.
    public static func legalEdge(_ from: UInt64, _ to: UInt64) -> Bool {
        if !isState(from) || !isState(to) {
            return false
        }
        return legalEdgeSet.contains([from, to])
    }

    /// A copy of the legal transition table as a sorted list of [from, to] pairs.
    public static func legalEdges() -> [[UInt64]] {
        return legalEdgeSet.sorted { a, b in a[0] != b[0] ? a[0] < b[0] : a[1] < b[1] }
    }

    /// The edge-legality gate: returns nothing iff (from -> to) is a legal A2A edge, else throws
    /// IllegalTransition (an unknown edge, a self-loop, an edge out of a terminal state, or an edge
    /// touching an undefined state). Fail-closed.
    public static func verifyTransition(_ from: UInt64, _ to: UInt64) throws {
        if !legalEdge(from, to) {
            throw NaalpError("IllegalTransition", "not a legal A2A transition edge")
        }
    }

    /// One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto the prior
    /// transition of the same task: prev is the prior transition's head (genesis for seq 0). Dated by seq.
    /// card is the content-id of the A2A Agent Card attestation (a C18 import) that binds this profile to
    /// an agent/operation.
    public struct Transition {
        public let task: [UInt8] // the task id (opaque bytes)
        public let card: [UInt8] // content-id of the bound A2A Agent Card attestation (the C18 import)
        public let from: UInt64  // the source state
        public let to: UInt64    // the target state
        public let seq: UInt64   // monotonic per-task chain position; seq 0's from MUST be the start state
        public let prev: [UInt8] // the prior transition's head (HEAD_SIZE bytes; genesis is zero)

        public init(task: [UInt8], card: [UInt8], from: UInt64, to: UInt64, seq: UInt64, prev: [UInt8]) {
            self.task = task
            self.card = card
            self.from = from
            self.to = to
            self.seq = seq
            self.prev = prev
        }

        func toMap() -> CborValue {
            return .m([
                (.u(1), .b(task)),
                (.u(2), .b(card)),
                (.u(3), .u(from)),
                (.u(4), .u(to)),
                (.u(5), .u(seq)),
                (.u(6), .b(prev)),
            ])
        }

        /// Deterministic-CBOR encoding {1:task,2:card,3:from,4:to,5:seq,6:prev}.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toMap()) }

        /// The chain head after this transition: SHA-384 of the transition body (48 octets).
        public func head() throws -> [UInt8] { return Array(SHA384.hash(data: Data(try bytes()))) }

        /// The transition's T1 content-id (50 octets).
        public func id() throws -> [UInt8] { return Cbor.contentId(try bytes()) }
    }

    /// Reconstruct a Transition from its body bytes alone. A body that is not exactly the {1,2,3,4,5,6}
    /// map with the right value types (or is non-canonical) is NameMalformed (fail-closed).
    public static func parseTransition(_ b: [UInt8]) throws -> Transition {
        guard let m = decodeMap(b) else {
            throw NaalpError("NameMalformed", "body is not a well-formed task transition")
        }
        guard let task = bstrField(m, 1), let card = bstrField(m, 2),
              let from = uintField(m, 3), let to = uintField(m, 4),
              let seq = uintField(m, 5), let prev = bstrField(m, 6) else {
            throw NaalpError("NameMalformed", "body is not a well-formed task transition")
        }
        return Transition(task: task, card: card, from: from, to: to, seq: seq, prev: prev)
    }

    /// Produce the tagged COSE_Sign1 object over the transition body (real Ed25519).
    public static func signTransition(_ t: Transition, _ seed: [UInt8]) throws -> [UInt8] {
        let prot = try protectedHeader(Cose.ALG_ED25519)
        let payload = try t.bytes()
        let sig = try Cose.ed25519Sign(seed, try Cose.toBeSignedRaw(prot, payload))
        return try Cose.assembleSign1Raw(prot, payload, sig)
    }

    /// Verify a signed transition's signature via the injected verifier and parse its body (no edge check).
    static func parseSignedTransition(_ obj: [UInt8], _ verify: Verify) throws -> Transition {
        let (prot, payload, sig) = try Cose.parseSign1Raw(obj)
        if !verify(try Cose.toBeSignedRaw(prot, payload), sig) {
            throw NaalpError("BadSignature", "signature does not verify")
        }
        return try parseTransition(payload)
    }

    /// Verify a transition's signature via the injected verifier, reconstruct it from the signed body
    /// bytes, AND check that its edge is legal. A bad signature is BadSignature; an illegal edge is
    /// IllegalTransition. Fail-closed. `verify` is `(msg, sig) -> Bool`.
    public static func verifyTransitionObject(_ obj: [UInt8], _ verify: Verify) throws -> Transition {
        let t = try parseSignedTransition(obj, verify)
        try verifyTransition(t.from, t.to)
        return t
    }

    /// Report whether a presented (possibly gappy) transition list breaks contiguity — a deleted/omitted
    /// or reordered transition — and, if so, the FIRST-BROKEN position. A contiguous list returns
    /// (0, false). (The gap-evident detector for the task chain, mirroring detectHole.)
    public static func detectTaskGap(_ transitions: [Transition]) -> (position: Int, gap: Bool) {
        var h = genesis()
        for (i, t) in transitions.enumerated() {
            if t.seq != UInt64(i) || t.prev != h {
                return (i, true)
            }
            h = (try? t.head()) ?? h
        }
        return (0, false)
    }

    /// Walk a task's transition chain OFFLINE (signature-independent) against the bound card attestation.
    /// Enforces, in order and fail-closed: (1) prev/seq linkage (each prev links to the prior head,
    /// genesis zero for seq 0; seq i == index) — a gap/reorder is TaskChainBroken; (2) the CARD BINDING
    /// (every transition's card equals `card`) — ForeignCard otherwise; and (3) the START STATE (seq-0's
    /// from is START_STATE), CONTIGUITY (each from == the prior to), and the LEGAL-EDGE TABLE at every
    /// step (including the terminal-cannot-continue rule, since a from-terminal edge is not in the table)
    /// — IllegalTransition otherwise. Returns the verified, ordered transitions.
    public static func verifyTaskChainStructure(_ transitions: [Transition], _ card: [UInt8]) throws -> [Transition] {
        var h = genesis()
        var prevTo: UInt64? = nil
        var out: [Transition] = []
        for (i, t) in transitions.enumerated() {
            if t.seq != UInt64(i) || t.prev != h {
                throw NaalpError("TaskChainBroken", "prev/seq does not chain to the previous transition")
            }
            if t.card != card {
                throw NaalpError("ForeignCard", "transition binds a card other than the profile's bound card")
            }
            if i == 0 {
                if t.from != START_STATE {
                    throw NaalpError("IllegalTransition", "the first transition must leave the start state")
                }
            } else if t.from != prevTo {
                throw NaalpError("IllegalTransition", "non-contiguous: this from must equal the prior to")
            }
            try verifyTransition(t.from, t.to) // an illegal edge (incl. a from-terminal edge)
            h = try t.head()
            prevTo = t.to
            out.append(t)
        }
        return out
    }

    /// Walk a task's transition chain against the authority's key and the bound card attestation. Each
    /// element is the tagged COSE_Sign1 object for one transition: its signature is verified (via the
    /// injected verifier) and its body parsed, then the whole chain's structure is checked
    /// (verifyTaskChainStructure). A bad signature is BadSignature; the structural verdicts are as
    /// verifyTaskChainStructure. `verify` is `(msg, sig) -> Bool` (Ed25519 on the pure Swift port).
    public static func verifyTaskChain(_ objs: [[UInt8]], _ card: [UInt8], _ verify: Verify) throws -> [Transition] {
        var transitions: [Transition] = []
        for obj in objs {
            transitions.append(try parseSignedTransition(obj, verify))
        }
        return try verifyTaskChainStructure(transitions, card)
    }

    // ---- small deterministic-CBOR field accessors (strict decode; NonCanonical -> nil) ------------

    static func decodeMap(_ b: [UInt8]) -> [(CborValue, CborValue)]? {
        guard let v = try? Cbor.decode(b), case let .m(pairs) = v else {
            return nil
        }
        return pairs
    }

    static func field(_ m: [(CborValue, CborValue)], _ k: UInt64) -> CborValue? {
        for (kk, vv) in m {
            if case let .u(n) = kk, n == k {
                return vv
            }
        }
        return nil
    }

    static func bstrField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> [UInt8]? {
        if case let .b(b)? = field(m, k) {
            return b
        }
        return nil
    }

    static func tstrField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> String? {
        if case let .t(s)? = field(m, k) {
            return s
        }
        return nil
    }

    static func uintField(_ m: [(CborValue, CborValue)], _ k: UInt64) -> UInt64? {
        if case let .u(u)? = field(m, k) {
            return u
        }
        return nil
    }
}
