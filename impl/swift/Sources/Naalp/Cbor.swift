// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Deterministic CBOR (RFC 8949 §4.2.1) for N-AALP — the C1 codec.
//
// An independent Swift implementation of the same deterministic profile the Go, Rust and
// Python reference implementations produce: shortest-form integer heads, no indefinite
// lengths, canonical (bytewise-ascending, by encoded key) map ordering, no duplicate keys.
// The strict decoder rejects any non-canonical encoding. The content id is
// multihash(0x20, 0x30, SHA-384(body)) over the deterministic body bytes (§2.3).

import Crypto
import Foundation

/// N-AALP errors carry a `kind` label mirroring the Python/Go/Rust reference SDKs so the
/// conformance adapter can format `<kind>: <message>` for a rejected (`invalid`) case.
public struct NaalpError: Error, CustomStringConvertible {
    public let kind: String
    public let message: String
    public init(_ kind: String, _ message: String) {
        self.kind = kind
        self.message = message
    }
    public var description: String { "\(kind): \(message)" }
}

/// The CBOR value model (mirrors the Go/Rust/Python cbor.Value variants).
public indirect enum CborValue {
    /// unsigned integer (major 0)
    case u(UInt64)
    /// negative integer (major 1); the associated value is the FIPS-style argument `arg`,
    /// so the logical value is `-1 - arg`.
    case n(UInt64)
    /// byte string (major 2)
    case b([UInt8])
    /// text string (major 3)
    case t(String)
    /// array (major 4)
    case a([CborValue])
    /// map (major 5); a list of (key, value) pairs
    case m([(CborValue, CborValue)])
    /// tag (major 6)
    case tag(UInt64, CborValue)
}

public enum Cbor {

    // --- encoding ---

    /// Encode the major-type head with a shortest-form argument.
    static func head(_ major: UInt8, _ n: UInt64) -> [UInt8] {
        let base = major << 5
        if n < 24 {
            return [base | UInt8(n)]
        }
        if n < 0x100 {
            return [base | 24, UInt8(n)]
        }
        if n < 0x1_0000 {
            return [base | 25, UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]
        }
        if n < 0x1_0000_0000 {
            return [base | 26,
                    UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                    UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]
        }
        return [base | 27,
                UInt8((n >> 56) & 0xff), UInt8((n >> 48) & 0xff),
                UInt8((n >> 40) & 0xff), UInt8((n >> 32) & 0xff),
                UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]
    }

    /// Bytewise-lexicographic comparison of two encoded keys (Python `bytes.__lt__`):
    /// compare byte by byte; if one is a prefix of the other, the shorter is smaller.
    static func lexLess(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        let m = Swift.min(a.count, b.count)
        var i = 0
        while i < m {
            if a[i] != b[i] { return a[i] < b[i] }
            i += 1
        }
        return a.count < b.count
    }

    static func lexEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        return a == b
    }

    /// Deterministic-CBOR encode a value; map keys are emitted in canonical order.
    public static func encode(_ v: CborValue) throws -> [UInt8] {
        switch v {
        case .u(let x):
            return head(0, x)
        case .n(let arg):
            return head(1, arg)
        case .b(let bytes):
            return head(2, UInt64(bytes.count)) + bytes
        case .t(let s):
            let bytes = Array(s.utf8)
            return head(3, UInt64(bytes.count)) + bytes
        case .a(let items):
            var out = head(4, UInt64(items.count))
            for it in items { out += try encode(it) }
            return out
        case .m(let pairs):
            var enc: [(k: [UInt8], val: [UInt8])] = []
            enc.reserveCapacity(pairs.count)
            for (k, val) in pairs {
                enc.append((try encode(k), try encode(val)))
            }
            enc.sort { lexLess($0.k, $1.k) }
            // reject duplicate keys (compare adjacent after the canonical sort)
            var i = 1
            while i < enc.count {
                if lexEqual(enc[i - 1].k, enc[i].k) {
                    throw NaalpError("NonCanonical", "duplicate map key")
                }
                i += 1
            }
            var out = head(5, UInt64(enc.count))
            for e in enc { out += e.k + e.val }
            return out
        case .tag(let n, let content):
            return head(6, n) + (try encode(content))
        }
    }

    // --- decoding ---

    /// A cursor over the input performing strict canonical decode.
    final class Reader {
        let data: [UInt8]
        var pos: Int = 0
        init(_ data: [UInt8]) { self.data = data }

        func remaining() -> Int { data.count - pos }

        func readByte() throws -> UInt8 {
            if pos >= data.count { throw NaalpError("NonCanonical", "truncated") }
            let b = data[pos]
            pos += 1
            return b
        }

        func readBytes(_ n: Int) throws -> [UInt8] {
            if remaining() < n { throw NaalpError("NonCanonical", "truncated") }
            let slice = Array(data[pos..<(pos + n)])
            pos += n
            return slice
        }

        /// Decode one item at the cursor, advancing it. Enforces shortest-form heads,
        /// forbids indefinite lengths, and enforces canonical, duplicate-free map keys.
        func decode() throws -> CborValue {
            if pos >= data.count { throw NaalpError("NonCanonical", "truncated") }
            let ib = data[pos]
            pos += 1
            let major = ib >> 5
            let ai = ib & 0x1F

            var arg: UInt64 = 0
            if ai == 31 {
                throw NaalpError("NonCanonical", "indefinite length")
            }
            if ai < 24 {
                arg = UInt64(ai)
            } else if ai == 24 {
                let b = try readByte()
                if b < 24 { throw NaalpError("NonCanonical", "non-shortest integer") }
                arg = UInt64(b)
            } else if ai == 25 {
                let bs = try readBytes(2)
                let v = (UInt64(bs[0]) << 8) | UInt64(bs[1])
                if v < 0x100 { throw NaalpError("NonCanonical", "non-shortest integer") }
                arg = v
            } else if ai == 26 {
                let bs = try readBytes(4)
                var v: UInt64 = 0
                for x in bs { v = (v << 8) | UInt64(x) }
                if v < 0x1_0000 { throw NaalpError("NonCanonical", "non-shortest integer") }
                arg = v
            } else if ai == 27 {
                let bs = try readBytes(8)
                var v: UInt64 = 0
                for x in bs { v = (v << 8) | UInt64(x) }
                if v < 0x1_0000_0000 { throw NaalpError("NonCanonical", "non-shortest integer") }
                arg = v
            } else {
                // ai in {28, 29, 30}
                throw NaalpError("NonCanonical", "reserved additional-info")
            }

            switch major {
            case 0:
                return .u(arg)
            case 1:
                return .n(arg)
            case 2:
                let n = try intFromArg(arg)
                return .b(try readBytes(n))
            case 3:
                let n = try intFromArg(arg)
                let bytes = try readBytes(n)
                guard let s = String(bytes: bytes, encoding: .utf8) else {
                    throw NaalpError("NonCanonical", "invalid utf-8 text string")
                }
                return .t(s)
            case 4:
                let n = try intFromArg(arg)
                var items: [CborValue] = []
                items.reserveCapacity(n)
                for _ in 0..<n { items.append(try decode()) }
                return .a(items)
            case 5:
                let n = try intFromArg(arg)
                var pairs: [(CborValue, CborValue)] = []
                pairs.reserveCapacity(n)
                var prev: [UInt8]? = nil
                for _ in 0..<n {
                    let before = pos
                    let k = try decode()
                    let kbytes = Array(data[before..<pos])
                    let val = try decode()
                    if let p = prev, !lexLess(p, kbytes) {
                        // current key <= prev key -> out of order or duplicate
                        throw NaalpError("NonCanonical", "map keys out of order or duplicate")
                    }
                    prev = kbytes
                    pairs.append((k, val))
                }
                return .m(pairs)
            case 6:
                let content = try decode()
                return .tag(arg, content)
            default:
                throw NaalpError("NonCanonical", "unsupported major type \(major)")
            }
        }

        private func intFromArg(_ arg: UInt64) throws -> Int {
            if arg > UInt64(Int.max) { throw NaalpError("NonCanonical", "length too large") }
            return Int(arg)
        }
    }

    /// Strict canonical decode: rejects any non-canonical encoding and trailing bytes.
    @discardableResult
    public static func decode(_ data: [UInt8]) throws -> CborValue {
        let r = Reader(data)
        let v = try r.decode()
        if r.remaining() != 0 {
            throw NaalpError("NonCanonical", "trailing bytes after top-level item")
        }
        return v
    }

    // --- content id ---

    /// Content id = multihash(0x20 [sha2-384], 0x30 [48], SHA-384(body-bytes)) (§2.3).
    public static func contentId(_ body: [UInt8]) -> [UInt8] {
        let digest = Array(SHA384.hash(data: Data(body)))
        return [0x20, 0x30] + digest
    }

    /// Content id over an encoded value.
    public static func contentId(_ v: CborValue) throws -> [UInt8] {
        return contentId(try encode(v))
    }
}
