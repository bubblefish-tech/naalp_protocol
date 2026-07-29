// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// SHA-2 helpers for N-AALP (the C0 primitives), backed by swift-crypto so the digests are
// byte-identical to the Go, Rust and Python reference implementations.

import Crypto
import Foundation

public enum Hashing {
    /// FIPS 180-4 SHA-384 of the message bytes.
    public static func sha384(_ msg: [UInt8]) -> [UInt8] {
        return Array(SHA384.hash(data: Data(msg)))
    }

    /// FIPS 180-4 SHA-256 of the message bytes.
    public static func sha256(_ msg: [UInt8]) -> [UInt8] {
        return Array(SHA256.hash(data: Data(msg)))
    }
}
