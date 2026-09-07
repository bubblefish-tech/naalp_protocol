// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C2 signing layer for the Swift SDK: the COSE_Sign1 (RFC 9052) signing-input and
// object assembly, plus Ed25519 (RFC 8032) via swift-crypto (Curve25519.Signing).
//
// ML-DSA (FIPS 204): the deterministic seed->key path is provided by MlDsa.swift (swift-crypto's
// vendored BoringSSL, deterministic sign via the CNaalpMldsa shim). coseSign1/coseVerify1 handle
// both Ed25519 and ML-DSA-65/-87, and the opt-in LAMPS composite (§4.2) lives in Composite.swift.

import Crypto
import Foundation

public enum Cose {
    public static let ALG_MLDSA65 = -49
    public static let ALG_MLDSA87 = -50
    public static let ALG_ED25519 = -19

    public static let TAG_SIGN1: UInt64 = 18

    /// The RFC 9052 §4.4 Sig_structure for a COSE_Sign1 over an already-serialized header.
    public static func toBeSignedRaw(_ protectedHeader: [UInt8], _ payload: [UInt8]) throws -> [UInt8] {
        return try Cbor.encode(.a([
            .t("Signature1"),
            .b(protectedHeader),
            .b([]),
            .b(payload),
        ]))
    }

    /// The tagged COSE_Sign1 object: 18([protected, {}, payload, signature]).
    public static func assembleSign1Raw(_ protectedHeader: [UInt8], _ payload: [UInt8], _ sig: [UInt8]) throws -> [UInt8] {
        return try Cbor.encode(.tag(TAG_SIGN1, .a([
            .b(protectedHeader),
            .m([]),
            .b(payload),
            .b(sig),
        ])))
    }

    /// Recover (protected, payload, sig) from a tagged COSE_Sign1 object.
    public static func parseSign1Raw(_ obj: [UInt8]) throws -> (protected: [UInt8], payload: [UInt8], sig: [UInt8]) {
        let v = try Cbor.decode(obj)
        guard case let .tag(n, content) = v, n == TAG_SIGN1, case let .a(items) = content else {
            throw NaalpError("Malformed", "not a tagged COSE_Sign1")
        }
        guard items.count == 4,
              case let .b(p) = items[0],
              case let .b(pl) = items[2],
              case let .b(s) = items[3] else {
            throw NaalpError("Malformed", "malformed COSE_Sign1 array")
        }
        return (p, pl, s)
    }

    // --- COSE_Sign (tag 98) multi-signature support: the §5.2 Rotation object co-signature ---

    public static let TAG_SIGN: UInt64 = 98

    /// One COSE_Signature protected header: {1: alg} (RFC 9052 §4). A negative COSE alg -49 encodes
    /// as a CBOR negative-int head with argument `-1 - alg`.
    public static func legProtected(_ alg: Int) throws -> [UInt8] {
        return try Cbor.encode(.m([(.u(1), .n(UInt64(-1 - alg)))]))
    }

    /// The per-signer COSE_Signature signing input for a COSE_Sign (RFC 9052 §4.4):
    /// det-CBOR(["Signature", body_protected, sign_protected, external_aad(empty), payload]). The
    /// five-element "Signature" structure (with the per-leg sign_protected) distinguishes a COSE_Sign
    /// leg from the four-element "Signature1" of a COSE_Sign1.
    public static func signatureToBeSigned(_ bodyProt: [UInt8], _ signerAlg: Int, _ payload: [UInt8]) throws -> [UInt8] {
        return try Cbor.encode(.a([
            .t("Signature"),
            .b(bodyProt),
            .b(try legProtected(signerAlg)),
            .b([]),
            .b(payload),
        ]))
    }

    /// Build one COSE_Signature leg: (leg_protected_bytes, signature_bytes). The ML-DSA leg is
    /// deterministic (rnd=0) over the per-signer ToBeSigned with the key derived from `seed`.
    public static func signatureLeg(_ bodyProt: [UInt8], _ alg: Int, _ seed: [UInt8], _ payload: [UInt8]) throws -> (prot: [UInt8], sig: [UInt8]) {
        let sprot = try legProtected(alg)
        let sig = try MlDsa.sign(seed, try signatureToBeSigned(bodyProt, alg, payload), alg)
        return (sprot, sig)
    }

    /// The tagged COSE_Sign object: 98([body_prot, {}, payload, [[sprot, {}, sig], ...]]).
    public static func assembleSignRaw(_ bodyProt: [UInt8], _ payload: [UInt8], _ legs: [(prot: [UInt8], sig: [UInt8])]) throws -> [UInt8] {
        let sigArr: [CborValue] = legs.map { .a([.b($0.prot), .m([]), .b($0.sig)]) }
        return try Cbor.encode(.tag(TAG_SIGN, .a([.b(bodyProt), .m([]), .b(payload), .a(sigArr)])))
    }

    /// Recover (body_prot, payload, legs) from a tagged COSE_Sign object.
    public static func parseSignRaw(_ obj: [UInt8]) throws -> (bodyProt: [UInt8], payload: [UInt8], legs: [(prot: [UInt8], sig: [UInt8])]) {
        let v = try Cbor.decode(obj)
        guard case let .tag(n, content) = v, n == TAG_SIGN, case let .a(items) = content else {
            throw NaalpError("Malformed", "not a tagged COSE_Sign")
        }
        guard items.count == 4,
              case let .b(bp) = items[0],
              case let .b(pl) = items[2],
              case let .a(sigs) = items[3] else {
            throw NaalpError("Malformed", "malformed COSE_Sign array")
        }
        var legs: [(prot: [UInt8], sig: [UInt8])] = []
        for sv in sigs {
            guard case let .a(e) = sv, e.count == 3,
                  case let .b(sprot) = e[0],
                  case let .b(lsig) = e[2] else {
                throw NaalpError("Malformed", "malformed COSE_Signature leg")
            }
            legs.append((sprot, lsig))
        }
        return (bp, pl, legs)
    }

    /// Extract the alg (label 1) value from a serialized leg protected header {1: alg}.
    public static func algFromProtected(_ prot: [UInt8]) throws -> Int {
        // §3.1.1 (R5): reject the redundant 0x41A0 encoding of an empty protected header (a bstr
        // wrapping an empty map; its unwrapped content is the single byte 0xA0) as NonCanonical,
        // before interpreting the header — the empty protected header is pinned to 0x40.
        if prot.count == 1 && prot[0] == 0xA0 {
            throw NaalpError("NonCanonical", "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)")
        }
        let v = try Cbor.decode(prot)
        guard case let .m(pairs) = v else { throw NaalpError("Malformed", "protected header not a map") }
        for (k, val) in pairs {
            if case let .u(kn) = k, kn == 1, case let .n(arg) = val {
                return -1 - Int(arg)
            }
        }
        throw NaalpError("Malformed", "no alg in protected header")
    }

    // --- Ed25519 (RFC 8032) via swift-crypto ---

    public static func ed25519Sign(_ seed: [UInt8], _ msg: [UInt8]) throws -> [UInt8] {
        if seed.count != 32 {
            throw NaalpError("Malformed", "ed25519 secret key must be a 32-byte seed")
        }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed))
        let sig = try key.signature(for: Data(msg))
        return Array(sig)
    }

    public static func ed25519Verify(_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        guard let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(pk)) else {
            return false
        }
        return pub.isValidSignature(Data(sig), for: Data(msg))
    }

    /// Sign a COSE_Sign1 over (protected, payload) with the seed-derived key for `alg` and assemble
    /// the tagged object. Ed25519 and ML-DSA-65/-87 are all deterministic-from-seed; ML-DSA uses no
    /// FIPS-204 context (pure COSE sign, distinct from the composite leg which uses the suite Label).
    public static func coseSign1(_ alg: Int, _ seed: [UInt8], _ protectedHeader: [UInt8], _ payload: [UInt8]) throws -> [UInt8] {
        let tbs = try toBeSignedRaw(protectedHeader, payload)
        let sig: [UInt8]
        if alg == ALG_ED25519 {
            sig = try ed25519Sign(seed, tbs)
        } else if alg == ALG_MLDSA65 || alg == ALG_MLDSA87 {
            sig = try MlDsa.sign(seed, tbs, alg)
        } else {
            throw NaalpError("UnknownAlg", "unknown alg \(alg)")
        }
        return try assembleSign1Raw(protectedHeader, payload, sig)
    }

    /// COSE_Sign1 verification for Ed25519 and ML-DSA-65/-87 (deterministic-from-seed via MlDsa).
    public static func coseVerify1(_ alg: Int, _ pk: [UInt8], _ obj: [UInt8]) throws -> Bool {
        let (protectedHeader, payload, sig) = try parseSign1Raw(obj)
        let tbs = try toBeSignedRaw(protectedHeader, payload)
        if alg == ALG_ED25519 {
            return ed25519Verify(pk, tbs, sig)
        }
        if alg == ALG_MLDSA65 || alg == ALG_MLDSA87 {
            return try MlDsa.verify(pk, tbs, sig, alg)
        }
        throw NaalpError("UnknownAlg", "unknown alg \(alg)")
    }
}
