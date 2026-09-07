// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C12 — foreign carriage by class for the Swift SDK (design.md §13; R-14.1..14.8, R-18.6).
//
// N-AALP carries a foreign agent protocol by wrapping its message, octet-for-octet, in a signed N-AALP
// carriage object whose effect, safety, identity, and audit apply, and whose foreign body is interpreted by
// a carriage CLASS — not a bespoke per-protocol mapping (R-14.1). There are five structured classes
// (JSONRPC, HTTP, MSG, STREAM, DOC) plus a universal OPAQUE class that makes any protocol — including one
// nobody has defined — carriable immediately on an experimental protocol id with no registration (R-14.1,
// R-18.6). The foreign field is carried VERBATIM and MUST NOT be re-serialized, canonicalized, summarized,
// or rewritten (R-14.4); N-AALP metadata is carried around it, never inside it. The carriage object's signer
// remains the authority — a foreign identity never becomes an N-AALP authorization identity (R-14.6).
//
// An independent transcription of impl/go/carriage (cross-read against impl/python/naalp/carriage.py),
// graded PER CLASS against its own oracle vectors/carriage/<class>/cases.json (values from the corpus, NEVER
// produced here). A carriage body is UNSIGNED by itself — the per-class body_hex ARE the byte parity; the
// R-14.6 authority property is exercised over a signed N-AALP envelope carrying the body. Every check is
// fail-closed (§13.6): a malformed or unrepresentable body is rejected whole with its named error.

import Foundation

public enum Carriage {
    // Carriage classes (design.md §13.2).
    public static let CLASS_JSONRPC: UInt64 = 0
    public static let CLASS_HTTP: UInt64 = 1
    public static let CLASS_MSG: UInt64 = 2
    public static let CLASS_STREAM: UInt64 = 3
    public static let CLASS_DOC: UInt64 = 4
    public static let CLASS_OPAQUE: UInt64 = 5

    static let classNames = ["JSONRPC", "HTTP", "MSG", "STREAM", "DOC", "OPAQUE"]

    /// The name of a class code (0..5), or "unknown".
    public static func className(_ c: UInt64) -> String {
        return c < UInt64(classNames.count) ? classNames[Int(c)] : "unknown"
    }

    /// The body of a carriage object (design.md §13.2). `klass` is the carriage class (spelled `klass`
    /// because `class` is a Swift keyword); `foreign` is the foreign message carried octet-for-octet (R-14.4).
    public struct CarriageBody {
        public let protocolID: UInt64
        public let klass: UInt64
        public let contentType: UInt64
        public let correlation: [UInt8]
        public let method: String
        public let foreign: [UInt8]

        public init(protocolID: UInt64, klass: UInt64, contentType: UInt64, correlation: [UInt8],
                    method: String, foreign: [UInt8]) {
            self.protocolID = protocolID
            self.klass = klass
            self.contentType = contentType
            self.correlation = correlation
            self.method = method
            self.foreign = foreign
        }

        /// The carriage body as a CBOR map {1: protocol_id, 2: class, 3: content_type, 4: correlation,
        /// 5: method, 6: foreign}.
        public func toValue() -> CborValue {
            return .m([
                (.u(1), .u(protocolID)),
                (.u(2), .u(klass)),
                (.u(3), .u(contentType)),
                (.u(4), .b(correlation)),
                (.u(5), .t(method)),
                (.u(6), .b(foreign)),
            ])
        }

        /// The deterministic-CBOR encoding of the carriage body.
        public func bytes() throws -> [UInt8] { return try Cbor.encode(toValue()) }
    }

    /// Reject a class code outside the defined set with a typed mapping error, never a silent drop (R-14.8).
    /// Returns normally when the class is representable.
    public static func validateClass(_ klass: UInt64) throws {
        if klass > CLASS_OPAQUE {
            throw NaalpError("MappingError", "an N-AALP semantic cannot be represented by this carriage class")
        }
    }

    /// Wrap a foreign message octet-for-octet in a carriage body (R-14.1, R-14.4). It does not parse,
    /// canonicalize, or rewrite the foreign bytes. An undefined protocol carries under OPAQUE with an
    /// experimental protocol id and zero new specification (R-18.6).
    public static func carry(protocolID: UInt64, klass: UInt64, contentType: UInt64, correlation: [UInt8],
                             method: String, foreign: [UInt8]) throws -> CarriageBody {
        try validateClass(klass)
        return CarriageBody(protocolID: protocolID, klass: klass, contentType: contentType,
                            correlation: correlation, method: method, foreign: foreign)
    }

    /// Parse a carriage body from a CBOR value, recovering the foreign field octet-for-octet. A structurally
    /// invalid body is Malformed; an unknown class is a MappingError. The mandatory foreign field (key 6)
    /// must be present.
    public static func carriageFromValue(_ v: CborValue) throws -> CarriageBody {
        guard case let .m(pairs) = v else {
            throw NaalpError("Malformed", "carriage body is not a map")
        }
        var protocolID: UInt64 = 0, klass: UInt64 = 0, contentType: UInt64 = 0
        var correlation: [UInt8] = [], foreign: [UInt8] = []
        var method = ""
        var haveForeign = false
        for (k, val) in pairs {
            guard case let .u(kn) = k else {
                throw NaalpError("Malformed", "non-uint carriage key")
            }
            switch kn {
            case 1:
                guard case let .u(u) = val else { throw NaalpError("Malformed", "protocol_id not a uint") }
                protocolID = u
            case 2:
                guard case let .u(u) = val else { throw NaalpError("Malformed", "class not a uint") }
                klass = u
            case 3:
                guard case let .u(u) = val else { throw NaalpError("Malformed", "content_type not a uint") }
                contentType = u
            case 4:
                guard case let .b(b) = val else { throw NaalpError("Malformed", "correlation not a bstr") }
                correlation = b
            case 5:
                guard case let .t(s) = val else { throw NaalpError("Malformed", "method not a tstr") }
                method = s
            case 6:
                guard case let .b(b) = val else { throw NaalpError("Malformed", "foreign not a bstr") }
                foreign = b
                haveForeign = true
            default:
                throw NaalpError("Malformed", "unknown carriage field \(kn)")
            }
        }
        if !haveForeign {
            throw NaalpError("Malformed", "carriage body missing the mandatory foreign field")
        }
        try validateClass(klass)
        return CarriageBody(protocolID: protocolID, klass: klass, contentType: contentType,
                            correlation: correlation, method: method, foreign: foreign)
    }

    /// The protocol-id range (design.md §13.4): reserved 0x00, standards 0x01-0x0F,
    /// experimental 0x10-0x7F (no registration), private 0x80-0xFF. protocol_id is one octet; anything wider
    /// is invalid.
    public static func protocolRange(_ id: UInt64) -> String {
        if id == 0x00 { return "reserved" }
        if id <= 0x0F { return "standards" }
        if id <= 0x7F { return "experimental" }
        if id <= 0xFF { return "private" }
        return "invalid"
    }

    /// Records whether a carried message was actually delivered. A report never claims delivery it did not
    /// achieve (R-14.8).
    public struct DeliveryReport {
        public let delivered: Bool
    }

    /// Produce a delivery report from the below-foreign outcome: a failed delivery throws NotDelivered
    /// (never a false "delivered"); a success returns DeliveryReport(delivered: true) (R-14.8).
    public static func report(_ deliveredBelow: Bool) throws -> DeliveryReport {
        if !deliveredBelow {
            throw NaalpError("NotDelivered", "a below-foreign failure; the message was not delivered")
        }
        return DeliveryReport(delivered: true)
    }

    /// The authorizing principal of a carriage object: the N-AALP signer of the object (envelope field 5),
    /// never any foreign principal named inside the foreign bytes (R-14.6). It reads only the signed
    /// envelope, never the carried foreign message.
    public static func carriageAuthority(_ o: Envelope.Object) -> [UInt8] { return o.signer }
}
