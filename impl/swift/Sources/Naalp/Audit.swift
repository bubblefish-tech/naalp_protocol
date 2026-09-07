// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C7 audit for the Swift SDK — the signed hash-chained receipt (the baseline single-authority
// ordering tier), the equivocation auditor and its non-repudiable fork proof, and the
// offline-checkable causal graph (design.md §8; R-8.1..8.6, R-12.2, R-12.3).
//
// An ordering authority records each accepted object by appending a signed Receipt
// {1: prev, 2: obj, 3: seq, 4: at}; the chain is tamper-evident because reordering, omission, or
// substitution breaks a `prev` link or a `seq` (§8.1). The authority never mutates the origin object
// to order it — ordering is an outer signed layer, and the object's own signature stays valid (§8.2).
// The causal graph is the authority-independent foundation: an edge "A causes B" is proven by B's
// signature over A's content id (envelope field 8) and is checkable offline; a total order is a policy
// layered over this partial order (§8.2). A cause an effect could not have seen (later position, or a
// cycle) is rejected (CausalViolation, §8.3). An auditor detects equivocation — two receipts by one
// authority at one seq naming different objects — from the signed receipts alone (§8.5), and mints a
// non-repudiable ForkProof carrying BOTH of the accused's signatures and an external monotonic counter
// (draft-01 finding #70).
//
// An independent transcription of impl/go/audit (cross-read against impl/python/naalp/audit.py),
// graded against the shared vectors/audit/cases.json. The causal partial order is checked by the
// shared Naalp.Graph (the same C7 foundation the reference reuses). NOTE: the audit topological order
// breaks ties by POSITION (authority seq) — distinct from the federation reconcile, whose tie-break is
// the content id (Naalp.Graph.reconcile).
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces — the receipt body/head, the chain final head,
// the ChainBroken linkage verdict, the fork-proof framing witness (preimage, signatures elided), the
// equivocation structural condition, and the causal verdicts + topological order — are all
// signature-independent and pure. Swift cannot deterministically sign or verify ML-DSA (FIPS 204) with
// SwiftDilithium 3.6.0, so the reference's ML-DSA receipt / fork-proof signatures are provided here as
// an Ed25519 (RFC 8032) signing DEMONSTRATION (Authority signing, Auditor observe, ForkProof verify,
// verifyChain take a real Ed25519 sign/verify path or an injected verify closure) — exercised in
// isolation, NOT corpus-graded. The reference's real ML-DSA-65 cross-language signed pins are NOT
// reproducible in the pure tier and are NOT fabricated here (honest F2/F4), mirroring the PHP port.

import Crypto
import Foundation

public enum Audit {

    /// The width of a chain head / prev link (SHA-384 = 48 bytes); genesis is zero.
    public static let HEAD_SIZE = 48

    /// A `(msg, sig) -> Bool` signature verifier the pure-tier signature gates take by injection
    /// (Ed25519 on this pure Swift port; the reference resolves an ML-DSA verifier for the signer).
    public typealias Verify = (_ msg: [UInt8], _ sig: [UInt8]) -> Bool

    /// One signed append to an ordering authority's chain (§8.1): `prev` is the hash of the previous
    /// receipt body (HEAD_SIZE bytes; genesis is zero); `obj` is the content id of the accepted object
    /// (never the object itself — §8.2); `seq` is the monotonic position; `at` is the authority's time
    /// anchor, epoch ms (independent of the signer's clock, R-8.4).
    public struct Receipt {
        public let prev: [UInt8]
        public let obj: [UInt8]
        public let seq: UInt64
        public let at: UInt64
        public init(prev: [UInt8], obj: [UInt8], seq: UInt64, at: UInt64) {
            self.prev = prev
            self.obj = obj
            self.seq = seq
            self.at = at
        }

        /// Deterministic-CBOR encoding of the receipt body {1: prev, 2: obj, 3: seq, 4: at}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(prev)),
                (.u(2), .b(obj)),
                (.u(3), .u(seq)),
                (.u(4), .u(at)),
            ]))
        }

        /// The chain head after this receipt: SHA-384 of the receipt body. Because the body carries
        /// prev, editing any receipt breaks the next receipt's linkage.
        public func head() throws -> [UInt8] {
            return Array(SHA384.hash(data: Data(try bytes())))
        }
    }

    /// A baseline single ordering authority (§8.4). It appends monotonic signed receipts over object
    /// content ids; it holds no object bodies and mutates none. PURE-ONLY Swift: signs each receipt
    /// body with a real Ed25519 (RFC 8032) key derived from a 32-byte seed, standing in for the
    /// reference's ML-DSA signer to exercise the signing binding.
    public final class Authority {
        private let seed: [UInt8]
        private var head: [UInt8]
        private var seq: UInt64

        public init(seed: [UInt8]) {
            self.seed = seed
            self.head = [UInt8](repeating: 0, count: HEAD_SIZE)
            self.seq = 0
        }

        /// Record acceptance of the object named by content id `obj` at time `at`, returning the signed
        /// receipt and its Ed25519 signature. Seq increases by one per append (monotonic).
        public func append(_ obj: [UInt8], _ at: UInt64) throws -> (Receipt, [UInt8]) {
            let r = Receipt(prev: head, obj: obj, seq: seq, at: at)
            let sig = try Cose.ed25519Sign(seed, try r.bytes())
            head = try r.head()
            seq += 1
            return (r, sig)
        }
    }

    /// Check a receipt chain's LINKAGE offline (signature-independent): each receipt's seq is the next
    /// expected value and its prev links to the previous receipt's head (genesis is zero). A broken
    /// link or a seq gap is ChainBroken — this alone detects any reorder, omission, or substitution
    /// (§8.1). (The signature check is layered on by verifyChain.)
    public static func verifyChainLinks(_ receipts: [Receipt]) throws {
        var head = [UInt8](repeating: 0, count: HEAD_SIZE)
        for (i, r) in receipts.enumerated() {
            if r.seq != UInt64(i) || r.prev != head {
                throw NaalpError("ChainBroken", "receipt prev/seq does not chain to the previous receipt")
            }
            head = try r.head()
        }
    }

    /// Check a receipt chain offline against the authority's key: the linkage (verifyChainLinks) AND,
    /// per receipt, that its signature verifies under the injected verifier. A broken link or a seq gap
    /// is ChainBroken; a bad signature is ReceiptUnsigned. `verify` is `(msg, sig) -> Bool` (Ed25519 on
    /// the pure Swift port).
    public static func verifyChain(_ receipts: [Receipt], _ sigs: [[UInt8]], _ verify: Verify) throws {
        if receipts.count != sigs.count {
            throw NaalpError("ChainBroken", "receipt/signature count mismatch")
        }
        var head = [UInt8](repeating: 0, count: HEAD_SIZE)
        for (i, r) in receipts.enumerated() {
            if r.seq != UInt64(i) || r.prev != head {
                throw NaalpError("ChainBroken", "receipt prev/seq does not chain to the previous receipt")
            }
            if !verify(try r.bytes(), sigs[i]) {
                throw NaalpError("ReceiptUnsigned", "receipt signature does not verify")
            }
            head = try r.head()
        }
    }

    /// An object cannot be created after the authority ordered it, so `created` MUST NOT exceed `at`
    /// (R-8.4). The receipt's `at` is signed and chained, so it is evidence a verifier checks
    /// independently of the signer's clock.
    public static func consistentWithAnchor(_ created: UInt64, _ at: UInt64) -> Bool {
        return created <= at
    }

    /// Non-repudiable evidence of equivocation (draft-01 §8.5, R-8.3): two validly-signed receipts by
    /// ONE authority at the SAME seq naming DIFFERENT objects, with the accused's OWN two signatures and
    /// an external monotonic counter — self-contained, so any third party verifies both signatures
    /// against the accused key with no further evidence and no repudiation.
    public struct ForkProof {
        public let signer: [UInt8]      // accused authority signer id; both sigs verify under its key
        public let extCounter: UInt64   // external monotonic counter bound into the proof (fixes replay/reorder)
        public let a: Receipt           // first receipt (a.bytes() is the signed input for sigA)
        public let sigA: [UInt8]        // the accused authority's signature over a.bytes()
        public let b: Receipt           // second receipt at the same seq naming a different object
        public let sigB: [UInt8]        // the accused authority's signature over b.bytes()

        public init(signer: [UInt8], extCounter: UInt64, a: Receipt, sigA: [UInt8], b: Receipt, sigB: [UInt8]) {
            self.signer = signer
            self.extCounter = extCounter
            self.a = a
            self.sigA = sigA
            self.b = b
            self.sigB = sigB
        }

        /// Deterministic-CBOR fork-proof body {1: signer, 2: ext_counter, 3: body_a, 4: sig_a,
        /// 5: body_b, 6: sig_b}. The two receipt bodies are embedded as the exact bytes each signature
        /// covers.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(signer)),
                (.u(2), .u(extCounter)),
                (.u(3), .b(try a.bytes())),
                (.u(4), .b(sigA)),
                (.u(5), .b(try b.bytes())),
                (.u(6), .b(sigB)),
            ]))
        }

        /// The deterministic-CBOR framing witness: the fork-proof body with the two signature
        /// byte-strings elided to empty. It is the structural authority the independent oracle
        /// reproduces byte-for-byte; the two (ML-DSA, in the reference) signatures are graded by
        /// cross-implementation byte-parity elsewhere. This is not a wire object; it exists only to
        /// grade the framing.
        public func preimage() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(signer)),
                (.u(2), .u(extCounter)),
                (.u(3), .b(try a.bytes())),
                (.u(4), .b([])),
                (.u(5), .b(try b.bytes())),
                (.u(6), .b([])),
            ]))
        }

        /// Accept iff ALL hold: (1) the signer id is present; (2) the two receipts share one seq;
        /// (3) they name DIFFERENT objects; and (4) BOTH signatures verify under the accused key. Any
        /// failure rejects the whole proof (fail-closed): a same-object / seq-mismatch / unnamed-signer
        /// proof is ForkProofInvalid (reached BEFORE the signature check), and a signature that does not
        /// verify is ReceiptUnsigned. `verify` MUST be the verifier resolved for `signer`.
        public func verify(_ verify: Verify) throws {
            if signer.isEmpty {
                throw NaalpError("ForkProofInvalid", "an unnamed accused is not evidence")
            }
            if a.seq != b.seq {
                throw NaalpError("ForkProofInvalid", "receipts at different sequence positions")
            }
            if a.obj == b.obj {
                throw NaalpError("ForkProofInvalid", "same object named twice — no equivocation")
            }
            let bodyA = try a.bytes()
            let bodyB = try b.bytes()
            if !verify(bodyA, sigA) || !verify(bodyB, sigB) {
                throw NaalpError("ReceiptUnsigned", "a signature does not verify under the accused key")
            }
        }
    }

    /// Assemble a fork proof from two conflicting signed receipts, the accused signer id, and an
    /// external monotonic counter. Performs no checks — ForkProof.verify is the fail-closed gate; this
    /// is the pure constructor (A9).
    public static func newForkProof(_ signer: [UInt8], _ a: Receipt, _ sigA: [UInt8],
                                    _ b: Receipt, _ sigB: [UInt8], _ extCounter: UInt64) -> ForkProof {
        return ForkProof(signer: signer, extCounter: extCounter, a: a, sigA: sigA, b: b, sigB: sigB)
    }

    /// Observes an authority's receipts and detects equivocation from the signed receipts alone (§8.5).
    /// On a conflict it mints a non-repudiable ForkProof carrying the accused signer id, both conflicting
    /// signatures, and an external monotonic counter (T2.1). The signature gate is an injected verifier
    /// (Ed25519 on the pure Swift port).
    public final class Auditor {
        private let verify: Verify
        private let signer: [UInt8]
        private var ext: UInt64
        private var seen: [UInt64: (Receipt, [UInt8])] = [:]

        public init(verify: @escaping Verify, signer: [UInt8], extBase: UInt64 = 0) {
            self.verify = verify
            self.signer = signer
            self.ext = extBase
        }

        /// Record a signed receipt. Throws ReceiptUnsigned on a bad signature. Returns a ForkProof
        /// (Equivocation) if a previously-seen receipt at the same seq named a different object — the
        /// proof carries the accused signer id, both signatures, and the auditor's current external
        /// counter, which then advances. Returns nil otherwise (including a benign exact duplicate).
        public func observe(_ r: Receipt, _ sig: [UInt8]) throws -> ForkProof? {
            if !verify(try r.bytes(), sig) {
                throw NaalpError("ReceiptUnsigned", "receipt signature does not verify")
            }
            if let prev = seen[r.seq] {
                if prev.0.obj != r.obj {
                    let fp = Audit.newForkProof(signer, prev.0, prev.1, r, sig, ext)
                    ext += 1
                    return fp
                }
                return nil
            }
            seen[r.seq] = (r, sig)
            return nil
        }
    }

    /// An object's place in the causal graph: its content id, the content ids of its causes (envelope
    /// field 8), and its ordering position (authority seq, or `created` absent a receipt).
    public struct CausalNode {
        public let id: [UInt8]
        public let causes: [[UInt8]]
        public let position: UInt64
        public init(id: [UInt8], causes: [[UInt8]], position: UInt64) {
            self.id = id
            self.causes = causes
            self.position = position
        }
    }

    /// Check the signed partial order (§8.2, §8.3): no object names a present cause whose position
    /// exceeds its own (a future cause it could not have seen), and the graph is acyclic. Either fault
    /// is CausalViolation. Delegates to the shared Naalp.Graph, which implements exactly this partial
    /// order.
    public static func verifyCausal(_ nodes: [CausalNode]) throws {
        try Graph.verifyCausal(nodes.map { Graph.Node(id: $0.id, causes: $0.causes, position: Int($0.position)) })
    }

    /// Return the causal nodes' content ids in a deterministic topological order (a cause before its
    /// effects). Ties among ready nodes break by (position, input index), so the order is reproducible.
    /// Throws CausalViolation if the graph does not verify. NOTE: the tie-break is by POSITION —
    /// distinct from the federation reconcile, whose tie-break is the content id (Naalp.Graph.reconcile).
    public static func topoOrder(_ nodes: [CausalNode]) throws -> [[UInt8]] {
        try verifyCausal(nodes)
        var idx: [[UInt8]: Int] = [:]
        for (i, n) in nodes.enumerated() {
            idx[n.id] = i
        }
        var indeg = [Int](repeating: 0, count: nodes.count)
        var effects = [[Int]](repeating: [], count: nodes.count) // cause index -> effect indices
        for (i, n) in nodes.enumerated() {
            for c in n.causes {
                if let j = idx[c] {
                    effects[j].append(i)
                    indeg[i] += 1
                }
            }
        }
        var done = [Bool](repeating: false, count: nodes.count)
        var order: [[UInt8]] = []
        while order.count < nodes.count {
            var pick = -1
            for i in 0..<nodes.count {
                if done[i] || indeg[i] != 0 { continue }
                if pick == -1 || nodes[i].position < nodes[pick].position {
                    pick = i // lowest position wins; equal positions keep the lower index (first seen)
                }
            }
            if pick == -1 {
                throw NaalpError("CausalViolation", "no ready node (unreachable after verifyCausal)")
            }
            done[pick] = true
            order.append(nodes[pick].id)
            for e in effects[pick] {
                indeg[e] -= 1
            }
        }
        return order
    }
}
