// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Opt-in LAMPS composite signature (alg -65537, design.md §4.2): an ML-DSA-65 leg and an Ed25519
// leg over a shared message representative M', ML-DSA leg first. Byte-identical to the Go (circl) /
// Rust (fips204) / Python (dilithium-py) / OpenSSL consensus and the committed non-circular oracle
// (tools/composite_oracle.py). PURELY ADDITIVE: new constants/methods only, no existing code changed.
import Crypto
import Foundation

extension Cose {
    /// §4.2 domain prefix.
    static let COMPOSITE_PREFIX = Array("CompositeAlgorithmSignatures2025".utf8)
    /// The suite Label for COMPSIG-MLDSA65-Ed25519-SHA512.
    static let COMPOSITE_LABEL = Array("COMPSIG-MLDSA65-Ed25519-SHA512".utf8)
    /// COSE alg id for the composite suite.
    public static let ALG_COMPOSITE_MLDSA65_ED25519 = -65537
    /// ML-DSA-65 leg size == the composite value split point.
    static let COMPOSITE_MLDSA_SIG_SIZE = 3309

    /// M' = Prefix || Label || len(ctx) || ctx || SHA-512(m) (§4.2). len(ctx) is a single length
    /// octet; PH is SHA-512; ctx is empty for N-AALP (octet 0x00, no ctx bytes).
    public static func computeMprime(_ label: [UInt8], _ ctx: [UInt8], _ m: [UInt8]) throws -> [UInt8] {
        guard ctx.count <= 255 else { throw NaalpError("Malformed", "composite context exceeds one length octet") }
        return COMPOSITE_PREFIX + label + [UInt8(ctx.count)] + ctx + Array(SHA512.hash(data: Data(m)))
    }

    /// The composite signature value over message `m`: mldsaSig(M') || edSig(M') (ML-DSA first, raw
    /// concat). The ML-DSA-65 leg is deterministic (rnd=0) with FIPS-204 context = the suite Label;
    /// the Ed25519 leg signs M' with no context.
    public static func compositeSign(_ mldsaSeed: [UInt8], _ edSeed: [UInt8], _ m: [UInt8]) throws -> [UInt8] {
        let mprime = try computeMprime(COMPOSITE_LABEL, [], m)
        let mldsaSig = try MlDsa.sign(mldsaSeed, mprime, ALG_MLDSA65, context: COMPOSITE_LABEL)
        let edSig = try ed25519Sign(edSeed, mprime)
        return mldsaSig + edSig
    }

    /// Verify a composite value fail-closed: the value must split into a 3309-byte ML-DSA leg and a
    /// 64-byte Ed25519 leg, and BOTH must verify over M' (a substituted leg fails the whole check).
    public static func compositeVerify(_ mldsaPub: [UInt8], _ edPub: [UInt8], _ m: [UInt8], _ sig: [UInt8]) throws -> Bool {
        guard sig.count == COMPOSITE_MLDSA_SIG_SIZE + 64 else { return false }
        let mprime = try computeMprime(COMPOSITE_LABEL, [], m)
        let mldsaSig = Array(sig[0 ..< COMPOSITE_MLDSA_SIG_SIZE])
        let edSig = Array(sig[COMPOSITE_MLDSA_SIG_SIZE...])
        let okMldsa = try MlDsa.verify(mldsaPub, mprime, mldsaSig, ALG_MLDSA65, context: COMPOSITE_LABEL)
        let okEd = ed25519Verify(edPub, mprime, edSig)
        return okMldsa && okEd
    }
}

extension Identity {
    /// The composite signer id (§5.1): multibase(base32, multihash(0x12 sha2-256, SHA-256(
    /// multicodec(mldsa) || mldsaPub || multicodec(ed25519) || edPub))). Substituting either leg key
    /// changes the id, so it self-certifies the composite key pair.
    public static func compositeSignerId(_ mldsaAlg: Int, _ mldsaPub: [UInt8], _ edPub: [UInt8]) throws -> String {
        guard let mcMldsa = multicodec[mldsaAlg], let mcEd = multicodec[Cose.ALG_ED25519] else {
            throw NaalpError("UnknownAlg", "no multicodec for composite algs (mldsa \(mldsaAlg))")
        }
        let preimage = uvarint(mcMldsa) + mldsaPub + uvarint(mcEd) + edPub
        let digest = Array(SHA256.hash(data: Data(preimage)))
        let mh = uvarint(MH_SHA256) + uvarint(UInt64(digest.count)) + digest
        return "b" + base32LowerNoPad(mh)
    }
}
