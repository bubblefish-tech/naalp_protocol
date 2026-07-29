// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP body builders for the Swift SDK — the deterministic-CBOR bodies of the spine records:
// approval + consume ledger (C6, §7), audit receipt (C7, §8), delivery update (C8, §9), stream
// open/commit/checkpoint + rolling commitment (C9, §10), foreign carriage (C12, §13), and the
// transport confidentiality boundary (C11, §12). Each body is exactly what the Go, Rust and
// Python reference implementations encode, so the bytes are byte-identical.

import Crypto
import Foundation

public enum Records {

    // --- C6 approval + consume ledger (§7) ---

    public static func approvalBody(_ approves: [UInt8], _ approver: String, _ grant: UInt64,
                                    _ nonce: [UInt8], _ notAfter: UInt64) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(approves)),
            (.u(2), .t(approver)),
            (.u(3), .u(grant)),
            (.u(4), .b(nonce)),
            (.u(5), .u(notAfter)),
        ]))
    }

    public static func approvalId(_ approves: [UInt8], _ approver: String, _ grant: UInt64,
                                  _ nonce: [UInt8], _ notAfter: UInt64) throws -> [UInt8] {
        return Cbor.contentId(try approvalBody(approves, approver, grant, nonce, notAfter))
    }

    public static func ledgerEntry(_ seq: UInt64, _ prev: [UInt8], _ approvalId: [UInt8], _ by: String) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .u(seq)),
            (.u(2), .b(prev)),
            (.u(3), .b(approvalId)),
            (.u(4), .t(by)),
        ]))
    }

    // --- C7 audit receipt (§8) ---

    public static func receiptBody(_ prev: [UInt8], _ obj: [UInt8], _ seq: UInt64, _ at: UInt64) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(prev)),
            (.u(2), .b(obj)),
            (.u(3), .u(seq)),
            (.u(4), .u(at)),
        ]))
    }

    public static func receiptHead(_ body: [UInt8]) -> [UInt8] {
        return Array(SHA384.hash(data: Data(body)))
    }

    // --- C8 delivery (§9) ---

    public static func deliveryUpdate(_ obj: [UInt8], _ stage: UInt64, _ at: UInt64) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(obj)),
            (.u(2), .u(stage)),
            (.u(3), .u(at)),
        ]))
    }

    // --- C9 streaming (§10) ---

    /// Rolling SHA-384 over the chunk data in absolute-offset order (R-10.2).
    public static func streamDigest(_ chunks: [(offset: UInt64, data: [UInt8])]) -> [UInt8] {
        let ordered = chunks.sorted { $0.offset < $1.offset }
        var hasher = SHA384()
        for c in ordered {
            hasher.update(data: Data(c.data))
        }
        return Array(hasher.finalize())
    }

    public static func streamOpenBody(_ streamId: [UInt8], _ effect: UInt64, _ approval: [UInt8], _ substream: UInt64) throws -> [UInt8] {
        var pairs: [(CborValue, CborValue)] = [
            (.u(1), .b(streamId)),
            (.u(2), .u(effect)),
            (.u(4), .u(substream)),
        ]
        if !approval.isEmpty {  // field 3 present only when an approval binding exists
            pairs.append((.u(3), .b(approval)))
        }
        return try Cbor.encode(.m(pairs))
    }

    public static func streamCommitBody(_ streamId: [UInt8], _ digest: [UInt8]) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(streamId)),
            (.u(2), .b(digest)),
        ]))
    }

    public static func streamCheckpointBody(_ streamId: [UInt8], _ throughOffset: UInt64, _ digestSoFar: [UInt8]) throws -> [UInt8] {
        return try Cbor.encode(.m([
            (.u(1), .b(streamId)),
            (.u(2), .u(throughOffset)),
            (.u(3), .b(digestSoFar)),
        ]))
    }

    // --- C12 foreign carriage (§13) ---

    public static let CLASS_JSONRPC: UInt64 = 0
    public static let CLASS_HTTP: UInt64 = 1
    public static let CLASS_MSG: UInt64 = 2
    public static let CLASS_STREAM: UInt64 = 3
    public static let CLASS_DOC: UInt64 = 4
    public static let CLASS_OPAQUE: UInt64 = 5

    public static func carriageBody(_ protocolId: UInt64, _ cls: UInt64, _ contentType: UInt64,
                                    _ correlation: [UInt8], _ method: String, _ foreign: [UInt8]) throws -> [UInt8] {
        if cls > CLASS_OPAQUE {
            throw NaalpError("MappingError", "carriage class \(cls) is not defined")
        }
        return try Cbor.encode(.m([
            (.u(1), .u(protocolId)),
            (.u(2), .u(cls)),
            (.u(3), .u(contentType)),
            (.u(4), .b(correlation)),
            (.u(5), .t(method)),
            (.u(6), .b(foreign)),
        ]))
    }

    // --- C11 transport confidentiality boundary (§12) ---

    // (confidential, peer_authenticated)
    static let transports: [String: (Bool, Bool)] = [
        "npamp": (true, true),
        "quic": (true, true),
        "websocket+wss": (true, false),
        "websocket+ws": (false, false),
        "https": (true, false),
        "http": (false, false),
    ]

    /// Apply the §12.3 confidentiality boundary + §12.4 peer-auth rule; returns the result label.
    public static func transportEmit(_ name: String, _ sensitive: Bool, _ requirePeerAuth: Bool) throws -> String {
        guard let t = transports[name] else {
            throw NaalpError("UnknownTransport", "unknown transport \(name)")
        }
        let (confidential, peerAuthenticated) = t
        if sensitive && !confidential {
            return "ConfidentialTransportRequired"
        }
        if requirePeerAuth && !peerAuthenticated {
            return "PeerUnauthenticated"
        }
        return "ok"
    }
}
