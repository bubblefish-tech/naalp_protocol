// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// ML-DSA (FIPS 204) for the N-AALP Swift SDK: deterministic (rnd=0) keygen-from-seed, sign, verify,
// byte-identical to the Go (circl) / Rust (fips204) / Python (dilithium-py) / OpenSSL consensus.
//
// ALL three operations route through the CNaalpMldsa C shim to swift-crypto's vendored BoringSSL,
// not the public MLDSA65/MLDSA87 Swift API, for two reasons: (1) the public sign API is HEDGED
// (fresh randomizer per signature) and cannot reproduce a pinned FIPS-204 known-answer vector, so
// signing reaches the internal BCM_mldsa{65,87}_sign_internal with the randomizer forced to 32 zero
// bytes; (2) on Apple platforms the public MLDSA65/87 types are gated behind a recent OS (system
// ML-DSA landed in macOS 26), whereas the BoringSSL BCM_* entry points are raw C with no OS gate —
// so routing keygen and verify through the shim too keeps the SDK buildable on macOS 10.15+ while
// producing bytes byte-identical to the Linux grade (same BoringSSL backend). See
// Sources/CNaalpMldsa (proven to link + byte-match on Linux AND macOS in CI, task #142).
import Foundation
import CNaalpMldsa

/// FIPS 204 ML-DSA-65 / ML-DSA-87, deterministic-from-seed, for the N-AALP signature suites.
public enum MlDsa {
    public static let ALG_MLDSA65 = -49
    public static let ALG_MLDSA87 = -50

    /// FIPS 204 encoded signature size for the given COSE alg id.
    static func signatureSize(_ alg: Int) throws -> Int {
        switch alg {
        case ALG_MLDSA65: return 3309
        case ALG_MLDSA87: return 4627
        default: throw NaalpError("UnknownAlg", "unknown ML-DSA alg \(alg)")
        }
    }

    /// FIPS-204 encoded public key size (bytes) for the given COSE alg id.
    static func publicKeySize(_ alg: Int) throws -> Int {
        switch alg {
        case ALG_MLDSA65: return 1952
        case ALG_MLDSA87: return 2592
        default: throw NaalpError("UnknownAlg", "unknown ML-DSA alg \(alg)")
        }
    }

    /// Raw FIPS-204 public key derived deterministically from a 32-byte seed (xi), via the BoringSSL
    /// shim (ungated on every platform; byte-identical to the cross-language keygen).
    public static func keygenFromSeed(_ seed: [UInt8], _ alg: Int) throws -> [UInt8] {
        guard seed.count == 32 else { throw NaalpError("Malformed", "ML-DSA seed must be 32 bytes, got \(seed.count)") }
        let size = try publicKeySize(alg)
        var out = [UInt8](repeating: 0, count: size)
        let status: Int
        switch alg {
        case ALG_MLDSA65:
            status = Int(naalp_mldsa65_pubkey_from_seed(seed, &out))
        case ALG_MLDSA87:
            status = Int(naalp_mldsa87_pubkey_from_seed(seed, &out))
        default:
            throw NaalpError("UnknownAlg", "unknown ML-DSA alg \(alg)")
        }
        // Low byte is the bcm_status: 0=approved / 1=not_approved are success, 2=failure.
        if (status & 0xff) == 2 { throw NaalpError("Internal", "ML-DSA keygen-from-seed failed (status \(status))") }
        return out
    }

    /// Deterministic (rnd=0) pure-ML-DSA signature over `msg`, key derived from the 32-byte seed.
    /// `context` (default empty) is the FIPS-204 context string; the opt-in LAMPS composite (§4.2)
    /// signs its ML-DSA leg with context = the suite Label.
    public static func sign(_ seed: [UInt8], _ msg: [UInt8], _ alg: Int, context: [UInt8] = []) throws -> [UInt8] {
        guard seed.count == 32 else { throw NaalpError("Malformed", "ML-DSA seed must be 32 bytes, got \(seed.count)") }
        guard context.count <= 255 else { throw NaalpError("Malformed", "ML-DSA context exceeds one length octet") }
        let size = try signatureSize(alg)
        var out = [UInt8](repeating: 0, count: size)
        let status: Int
        switch alg {
        case ALG_MLDSA65:
            status = Int(naalp_mldsa65_det_sign(seed, msg, msg.count, context, context.count, &out))
        case ALG_MLDSA87:
            status = Int(naalp_mldsa87_det_sign(seed, msg, msg.count, context, context.count, &out))
        default:
            throw NaalpError("UnknownAlg", "unknown ML-DSA alg \(alg)")
        }
        // The low byte is the sign bcm_status: 0=approved / 1=not_approved are success, 2=failure.
        if (status & 0xff) == 2 { throw NaalpError("Internal", "ML-DSA deterministic sign failed (status \(status))") }
        return out
    }

    /// Verify a pure-ML-DSA signature over `msg` against a raw public key, via the BoringSSL shim
    /// (ungated on every platform). `context` (default empty) is the FIPS-204 context string; the
    /// composite verifies its ML-DSA leg with context = Label. Fail-closed: a malformed public key
    /// or signature yields `false`, never a false accept.
    public static func verify(_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8], _ alg: Int, context: [UInt8] = []) throws -> Bool {
        guard context.count <= 255 else { throw NaalpError("Malformed", "ML-DSA context exceeds one length octet") }
        let ok: Int32
        switch alg {
        case ALG_MLDSA65:
            ok = naalp_mldsa65_verify(pk, pk.count, msg, msg.count, sig, sig.count, context, context.count)
        case ALG_MLDSA87:
            ok = naalp_mldsa87_verify(pk, pk.count, msg, msg.count, sig, sig.count, context, context.count)
        default:
            throw NaalpError("UnknownAlg", "unknown ML-DSA alg \(alg)")
        }
        return ok == 1
    }
}
