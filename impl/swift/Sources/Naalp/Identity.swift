// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C4 identity for the Swift SDK: the self-certifying signer id (§5.1) and the NFC rule.
//
// signer id = multibase(base32, multihash(0x12 sha2-256, SHA-256(multicodec(mc) || pubkey))),
// identical in form to the N-PAMP PeerHandle. Multicodec codes are from the multiformats
// registry: ed25519-pub 0xed, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212; multihash sha2-256 0x12.

import Crypto
import Foundation

public enum Identity {
    static let multicodec: [Int: UInt64] = [
        Cose.ALG_ED25519: 0xED,
        Cose.ALG_MLDSA65: 0x1211,
        Cose.ALG_MLDSA87: 0x1212,
    ]
    static let MH_SHA256: UInt64 = 0x12

    static let base32Alphabet = Array("abcdefghijklmnopqrstuvwxyz234567")

    /// Unsigned LEB128 varint (multiformats `uvarint`).
    static func uvarint(_ value: UInt64) -> [UInt8] {
        var n = value
        var out: [UInt8] = []
        while true {
            let b = UInt8(n & 0x7F)
            n >>= 7
            if n != 0 {
                out.append(b | 0x80)
            } else {
                out.append(b)
                return out
            }
        }
    }

    /// RFC 4648 base32, lowercase, no padding (== Python `b32encode().lower().rstrip("=")`).
    static func base32LowerNoPad(_ data: [UInt8]) -> String {
        var out = ""
        var value = 0
        var bits = 0
        for byte in data {
            value = (value << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                let idx = (value >> (bits - 5)) & 31
                out.append(base32Alphabet[idx])
                bits -= 5
            }
            value &= (1 << bits) - 1
        }
        if bits > 0 {
            let idx = (value << (5 - bits)) & 31
            out.append(base32Alphabet[idx])
        }
        return out
    }

    /// The self-certifying signer id for (alg, pubkey), or throws UnknownAlg.
    public static func signerId(_ alg: Int, _ pubkey: [UInt8]) throws -> String {
        guard let mc = multicodec[alg] else {
            throw NaalpError("UnknownAlg", "no multicodec for alg \(alg)")
        }
        let tagged = uvarint(mc) + pubkey
        let digest = Array(SHA256.hash(data: Data(tagged)))
        let mh = uvarint(MH_SHA256) + uvarint(UInt64(digest.count)) + digest
        return "b" + base32LowerNoPad(mh)
    }

    public static func checkSigner(_ claimed: String, _ alg: Int, _ pubkey: [UInt8]) throws {
        if try signerId(alg, pubkey) != claimed {
            throw NaalpError("SignerMismatch", "signer id does not recompute from the key")
        }
    }

    /// Reject an identity/scope string that is not Unicode NFC (§3.1, R-3.3).
    ///
    /// Swift `String` equality is canonical-equivalence-aware, so comparing a string to its own
    /// precomposed (NFC) form with `!=`/`==` is ALWAYS "equal" — the check would never reject a
    /// non-NFC (e.g. NFD) input. Compare the exact UTF-8 byte sequences instead, which are distinct
    /// for a decomposed vs. composed form and correctly detect a non-NFC string.
    public static func requireNFC(_ s: String) throws {
        if Array(s.utf8) != Array(s.precomposedStringWithCanonicalMapping.utf8) {
            throw NaalpError("NonNFC", "string is not Unicode NFC")
        }
    }
}

// ---- key rotation (design §5.2): the co-signed old->new link ---------------------------------
//
// ADDED ADDITIVELY (Wave D, rooms port): the self-certifying signer id survives a key rotation. A
// RotationRecord binds the old id to the new id from a not_before position, co-signed by BOTH keys,
// so attribution to the durable identity is preserved across rotation (R-1.4). This is the C4
// primitive the Delivery-Model-B principal registry (Rooms.PrincipalRegistry) composes on for a
// rotation-authorised rebind — placed in the identity spine exactly as impl/go/identity,
// impl/python/naalp/identity, and impl/php/src/Identity.php place it, NOT inside Rooms. New
// types/methods only; no existing Identity code is changed (PURELY ADDITIVE — zero deletions).
extension Identity {
    /// Links an old signer id to a new one from `notBefore` (§5.2). Its signed bytes are the
    /// deterministic-CBOR map {1: old, 2: new, 3: not_before}, byte-identical to the Go/Python/PHP
    /// RotationRecord via the shared Cbor encoder.
    public struct RotationRecord {
        public let old: String
        public let new: String
        public let notBefore: UInt64

        public init(old: String, new: String, notBefore: UInt64) {
            self.old = old
            self.new = new
            self.notBefore = notBefore
        }

        /// Deterministic-CBOR encoding of the rotation body {1: old, 2: new, 3: not_before}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .t(old)),
                (.u(2), .t(new)),
                (.u(3), .u(notBefore)),
            ]))
        }
    }

    /// Co-sign a rotation with BOTH the old and new keys (§5.2). PURE-ONLY Swift: each leg is a real
    /// deterministic Ed25519 (RFC 8032) signature over the rotation body — the pure-tier stand-in for
    /// the reference's deterministic ML-DSA co-signature. Returns (oldSig, newSig).
    public static func signRotation(_ r: RotationRecord, _ oldSeed: [UInt8], _ newSeed: [UInt8]) throws -> (oldSig: [UInt8], newSig: [UInt8]) {
        let m = try r.bytes()
        return (try Cose.ed25519Sign(oldSeed, m), try Cose.ed25519Sign(newSeed, m))
    }

    /// Confirm a rotation is authorized (§5.2, §5.5): BOTH keys derive the ids in the record AND BOTH
    /// signatures verify over the rotation body. Any failure — an id that does not recompute from its
    /// key, an unregistered algorithm, or a signature that does not verify — collapses to
    /// RotationUnauthorized (fail-closed). A substitution not co-signed by the old key cannot pass, so
    /// the durable id cannot be hijacked to an unrelated key. PURE-ONLY Swift: only Ed25519 is a real
    /// verify path; a non-Ed25519 leg has no deterministic Swift verifier and is refused fail-closed
    /// (documented pure-tier behaviour, mirroring the PHP port).
    public static func verifyRotation(_ r: RotationRecord, _ oldAlg: Int, _ oldPub: [UInt8],
                                      _ newAlg: Int, _ newPub: [UInt8], _ oldSig: [UInt8], _ newSig: [UInt8]) throws {
        do {
            try checkSigner(r.old, oldAlg, oldPub)
            try checkSigner(r.new, newAlg, newPub)
        } catch {
            throw NaalpError("RotationUnauthorized", "a rotation key does not derive its recorded signer id")
        }
        let m = try r.bytes()
        if !rotationLegVerifies(oldAlg, oldPub, m, oldSig) || !rotationLegVerifies(newAlg, newPub, m, newSig) {
            throw NaalpError("RotationUnauthorized", "a rotation signature does not verify under its key")
        }
    }

    /// One rotation-leg signature check. PURE-ONLY: Ed25519 is verified with real crypto; any other alg
    /// has no deterministic Swift verifier and is refused fail-closed.
    static func rotationLegVerifies(_ alg: Int, _ pub: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        if alg == Cose.ALG_ED25519 {
            return Cose.ed25519Verify(pub, msg, sig)
        }
        return false
    }
}

// ---- revocation, foreign-identity linkage, and the durable identity thread (design.md §5.3/§5.4,
// R-1.4) -----------------------------------------------------------------------------------------
//
// PORTED from impl/go/identity/identity.go and impl/rust/src/identity.rs (the reference; ported,
// not invented) as the eleven RECORD + THREAD surfaces graded by vectors/identity_records/cases.json
// (F3): RevocationRecord, RevokedAt, VerifyRevocation, ForeignLinkRecord, VerifyForeignLink,
// RotationEvidence, Thread, Thread.attributable, ResolveThread. Unlike the Wave-D rotation additions
// above (which predate the Swift ML-DSA shim and stayed deliberately Ed25519-only / fail-closed
// on ML-DSA), this block uses REAL ML-DSA-65/-87 verification via MlDsa.verify (now available,
// see MlDsa.swift/#142) because every §5.3/§5.4/§5.2-evidence vector in the oracle signs with
// candidate_alg/old_alg/new_alg == -49 (ML-DSA-65) — an Ed25519-only path could not grade against
// this corpus at all. PURELY ADDITIVE: no existing Identity code above is changed.
extension Identity {
    /// Raw (non-COSE-wrapped) signature verification dispatched by COSE alg id — the Swift
    /// equivalent of the Go/Rust `cose.Verifier.VerifyRaw`/`CoseVerifier::verify_raw` used
    /// throughout VerifyRevocation, VerifyForeignLink, and the rotation co-signature check below.
    /// Fail-closed: an unrecognized alg (never reached once the caller has already recomputed a
    /// signer id, which rejects UnknownAlg first) or any verification failure returns `false`.
    static func rawVerify(_ alg: Int, _ pub: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        if alg == Cose.ALG_ED25519 {
            return Cose.ed25519Verify(pub, msg, sig)
        }
        if alg == Cose.ALG_MLDSA65 || alg == Cose.ALG_MLDSA87 {
            return (try? MlDsa.verify(pub, msg, sig, alg)) ?? false
        }
        return false
    }

    // ---- RevocationRecord (§5.3) --------------------------------------------------------------

    /// Marks a key dead from `notAfter` (§5.3). Signed bytes: deterministic-CBOR
    /// {1: key, 2: not_after}.
    public struct RevocationRecord {
        public let key: String
        public let notAfter: UInt64

        public init(key: String, notAfter: UInt64) {
            self.key = key
            self.notAfter = notAfter
        }

        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .t(key)),
                (.u(2), .u(notAfter)),
            ]))
        }
    }

    /// Confirms a revocation is validly signed (§5.3): by the key it revokes, or by a
    /// deployer-configured recovery key. `recoveryIDs` is the deployer's set of authorized
    /// recovery-key signer ids; a revocation whose signer is neither `r.key` nor a member of
    /// `recoveryIDs` is rejected SignerMismatch (§5.5), fail-closed — an empty `recoveryIDs`
    /// admits only the revoked key itself. The signer id is recomputed from the presented key and
    /// checked BEFORE the signature (membership before signature).
    public static func verifyRevocation(_ r: RevocationRecord, _ alg: Int, _ pub: [UInt8],
                                        _ sig: [UInt8], _ recoveryIDs: [String]) throws {
        let id = try signerId(alg, pub) // UnknownAlg propagates unchanged
        var authorized = id == r.key
        if !authorized {
            for rid in recoveryIDs where rid == id {
                authorized = true
                break
            }
        }
        guard authorized else {
            throw NaalpError("SignerMismatch", "signer id does not equal the recomputed id and is not an authorized recovery id")
        }
        let m = try r.bytes()
        guard rawVerify(alg, pub, m, sig) else {
            throw NaalpError("BadSignature", "signature verification failed")
        }
    }

    /// Reports whether an object fixed at authoritative position `posTime` is after the
    /// revocation (KeyRevoked); objects fixed at or before `notAfter` stay valid (§5.3).
    public static func revokedAt(_ r: RevocationRecord, _ posTime: UInt64) -> Bool {
        return posTime > r.notAfter
    }

    // ---- ForeignLinkRecord (§5.4) --------------------------------------------------------------

    /// Cross-signs a foreign identity to a signer id (§5.4). Signed bytes: deterministic-CBOR
    /// {1: controls, 2: foreign_id, 3: not_after}. It is signed by the FOREIGN identity's key.
    public struct ForeignLinkRecord {
        public let controls: String
        public let foreignID: String
        public let notAfter: UInt64

        public init(controls: String, foreignID: String, notAfter: UInt64) {
            self.controls = controls
            self.foreignID = foreignID
            self.notAfter = notAfter
        }

        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .t(controls)),
                (.u(2), .t(foreignID)),
                (.u(3), .u(notAfter)),
            ]))
        }
    }

    /// Reports whether a foreign-identity link confers linkage at time `now`. A non-NFC
    /// `foreignID` is rejected (NonNFC). An expired link or a bad cross-signature confers NO
    /// linkage but is not itself an error — it simply does not link (the object remains valid on
    /// its own signature, §5.4/§5.5). It NEVER overrides the key-derived id.
    public static func verifyForeignLink(_ r: ForeignLinkRecord, _ alg: Int, _ foreignPub: [UInt8],
                                         _ sig: [UInt8], _ now: UInt64) throws -> Bool {
        try requireNFC(r.foreignID)
        if now > r.notAfter {
            return false // expired: confers no authority (ignored)
        }
        let m = try r.bytes()
        if !rawVerify(alg, foreignPub, m, sig) {
            return false // bad/absent cross-signature: no linkage
        }
        return true
    }

    // ---- durable identity thread (rotation-surviving attribution, R-1.4) ----------------------

    /// One verified rotation step: the record plus the two keys (alg + raw public key) and their
    /// co-signatures. The Swift equivalent of the Go/Rust `RotationEvidence{Record, OldV, NewV,
    /// OldPub, NewPub, OldSig, NewSig}` — an alg id stands in for the Go/Rust `cose.Verifier`
    /// object, since Swift's identity layer verifies by (alg, pubkey) rather than a verifier type.
    public struct RotationEvidence {
        public let record: RotationRecord
        public let oldAlg: Int
        public let oldPub: [UInt8]
        public let oldSig: [UInt8]
        public let newAlg: Int
        public let newPub: [UInt8]
        public let newSig: [UInt8]

        public init(record: RotationRecord, oldAlg: Int, oldPub: [UInt8], oldSig: [UInt8],
                    newAlg: Int, newPub: [UInt8], newSig: [UInt8]) {
            self.record = record
            self.oldAlg = oldAlg
            self.oldPub = oldPub
            self.oldSig = oldSig
            self.newAlg = newAlg
            self.newPub = newPub
            self.newSig = newSig
        }
    }

    /// A durable identity: a root signer id continued by a chain of rotations.
    public struct Thread {
        public let root: String // the id the thread is named by (the first key)
        public let current: String // the id after the latest rotation
        public let chain: [String] // root, then each rotated-to id in order

        public init(root: String, current: String, chain: [String]) {
            self.root = root
            self.current = current
            self.chain = chain
        }

        /// Reports whether an object whose body signer id is `signer` belongs to this durable
        /// thread (any id in the chain, including a pre-rotation key, R-1.4).
        public func attributable(_ signer: String) -> Bool {
            return chain.contains(signer)
        }
    }

    /// Verifies one rotation evidence step is authorized: both keys derive the record's ids
    /// (§5.1) and both co-signatures verify over `record.bytes()`. Any failure collapses to
    /// RotationUnauthorized (fail-closed), matching Go's VerifyRotation / Rust's verify_rotation.
    static func verifyRotationEvidence(_ e: RotationEvidence) throws {
        do {
            try checkSigner(e.record.old, e.oldAlg, e.oldPub)
            try checkSigner(e.record.new, e.newAlg, e.newPub)
        } catch {
            throw NaalpError("RotationUnauthorized", "a rotation key does not derive its recorded signer id")
        }
        let m = try e.record.bytes()
        if !rawVerify(e.oldAlg, e.oldPub, m, e.oldSig) || !rawVerify(e.newAlg, e.newPub, m, e.newSig) {
            throw NaalpError("RotationUnauthorized", "a rotation signature does not verify under its key")
        }
    }

    /// Verifies an ordered rotation chain and returns the durable identity thread. Each rotation
    /// must be authorized (co-signed) and link the previous `new` to the next `old`; a break
    /// yields RotationUnauthorized. A receipt signed under any id in `chain` is attributable to
    /// `root`, so it stays attributable after rotation (R-1.4).
    public static func resolveThread(_ evs: [RotationEvidence]) throws -> Thread {
        guard !evs.isEmpty else {
            throw NaalpError("RotationUnauthorized", "no rotation evidence")
        }
        let root = evs[0].record.old
        var chain = [root]
        var prevNew = root
        for e in evs {
            if e.record.old != prevNew {
                throw NaalpError("RotationUnauthorized", "rotation chain is not contiguous")
            }
            try verifyRotationEvidence(e)
            chain.append(e.record.new)
            prevNew = e.record.new
        }
        return Thread(root: root, current: prevNew, chain: chain)
    }
}
