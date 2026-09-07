// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Known-answer tests for the deterministic (rnd=0) ML-DSA path (MlDsa.swift + the CNaalpMldsa C
// shim over swift-crypto's vendored BoringSSL). These demonstrate the ML-DSA core in isolation:
// keygen-from-seed reproduces the composite oracle's public key, deterministic signing reproduces
// the composite oracle's ML-DSA leg (value_hex[:3309]) and is byte-stable across two signs (rnd=0),
// and verify accepts a good signature and rejects a tampered one. Values are the committed composite
// fixture (tools/composite_oracle.py, ML-DSA-65 seed = bytes(0..31)); the full byte-for-byte
// cross-language grade lives in the naalp-conform corpus (composite.sign consensus gate).
import XCTest
import Naalp

final class MlDsaKatTests: XCTestCase {
    private func hexToBytes(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }
    private func hex<S: Sequence>(_ b: S) -> String where S.Element == UInt8 {
        b.map { String(format: "%02x", $0) }.joined()
    }

    private let seed = Array(UInt8(0)...UInt8(31))
    private let label = Array("COMPSIG-MLDSA65-Ed25519-SHA512".utf8)
    // M' (raw_tbs) = CompositePrefix || Label || 0x00 || SHA-512("parity-tbs-fixed"), 127 bytes.
    private let mprimeHex =
        "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d505349472d4d4c44534136352d456432353531392d5348413531320025a030ff90045a5dc053f7df1ad32b232056020a01d0ef32f6acbea5f525c8532d0a7ee08a8823f7eafaca57e1ab5bb06abc1ed6defb201bb81ee1be9275a30d"

    func testKeygenFromSeedReproducesOraclePublicKey65() throws {
        let pk = try MlDsa.keygenFromSeed(seed, MlDsa.ALG_MLDSA65)
        XCTAssertEqual(pk.count, 1952)
        XCTAssertEqual(hex(pk.prefix(8)), "48683d91978e31eb")
    }

    func testKeygenFromSeed87Length() throws {
        let pk = try MlDsa.keygenFromSeed(seed, MlDsa.ALG_MLDSA87)
        XCTAssertEqual(pk.count, 2592)
    }

    func testDeterministicSignReproducesCompositeMldsaLeg() throws {
        let mprime = hexToBytes(mprimeHex)
        XCTAssertEqual(mprime.count, 127)
        let s1 = try MlDsa.sign(seed, mprime, MlDsa.ALG_MLDSA65, context: label)
        let s2 = try MlDsa.sign(seed, mprime, MlDsa.ALG_MLDSA65, context: label)
        XCTAssertEqual(s1.count, 3309)
        XCTAssertEqual(s1, s2, "ML-DSA signing must be deterministic (rnd = 0)")
        XCTAssertEqual(hex(s1.prefix(24)), "ef8aa0a151bbc14b7167eff220c10c3bde251846ed032139")
    }

    func testVerifyAcceptsGoodAndRejectsTampered() throws {
        let pk = try MlDsa.keygenFromSeed(seed, MlDsa.ALG_MLDSA65)
        let mprime = hexToBytes(mprimeHex)
        let sig = try MlDsa.sign(seed, mprime, MlDsa.ALG_MLDSA65, context: label)
        XCTAssertTrue(try MlDsa.verify(pk, mprime, sig, MlDsa.ALG_MLDSA65, context: label))
        var tampered = sig
        tampered[0] ^= 0xff
        XCTAssertFalse(try MlDsa.verify(pk, mprime, tampered, MlDsa.ALG_MLDSA65, context: label))
    }
}
