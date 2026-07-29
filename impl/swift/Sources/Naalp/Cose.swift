// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C2 signing layer for the Swift SDK: the COSE_Sign1 (RFC 9052) signing-input and
// object assembly, plus Ed25519 (RFC 8032) via swift-crypto (Curve25519.Signing).
//
// ML-DSA (FIPS 204) NOTE: the pinned dependency SwiftDilithium 3.6.0 exposes NO seed-based
// (NIST ACVP xi) key derivation — its only key generation is `Dilithium.GenerateKeyPair(kind:)`
// (internally random), and `SecretKey(keyBytes:)` requires the full expanded secret key
// (`skSize` bytes), not the 32-byte seed. The conformance corpus supplies a 32-byte seed and
// expects the exact public key / a deterministic signature, so the deterministic seed->key
// path this contract needs cannot be produced with SwiftDilithium 3.6.0. The adapter therefore
// returns `skipped` (Unimplemented, never a false green) for `mldsa.keygen`, `cose.sign1`, and
// the ML-DSA branch of `cose.verify1`, exactly as the contract sanctions for a language whose
// available library has no deterministic-from-seed FIPS 204 path. Ed25519 and every pure spine
// op are fully implemented and graded.

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

    /// COSE_Sign1 verification. The ML-DSA branch is unavailable (see the ML-DSA NOTE above)
    /// and signals that with an `Unavailable`-kind error the adapter maps to `skipped`.
    public static func coseVerify1(_ alg: Int, _ pk: [UInt8], _ obj: [UInt8]) throws -> Bool {
        let (protectedHeader, payload, sig) = try parseSign1Raw(obj)
        let tbs = try toBeSignedRaw(protectedHeader, payload)
        if alg == ALG_ED25519 {
            return ed25519Verify(pk, tbs, sig)
        }
        if alg == ALG_MLDSA65 || alg == ALG_MLDSA87 {
            throw NaalpError("Unavailable", "ML-DSA verification requires a deterministic-from-seed FIPS 204 path unavailable in SwiftDilithium 3.6.0")
        }
        throw NaalpError("UnknownAlg", "unknown alg \(alg)")
    }
}
