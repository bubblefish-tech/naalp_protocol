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
