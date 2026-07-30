// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// naalp-adapter — the Swift N-AALP conformance adapter.
//
// Wraps the impl/swift `Naalp` SDK behind the length-prefixed JSON op protocol the naalp-conform
// runner drives (harness/INSTRUCTIONS.md): a 4-byte little-endian length + UTF-8 JSON {"op","in"}
// request on stdin, and a {"out"|"error"|"skipped"} response in the same framing on stdout,
// flushed after each. Every pure spine op plus SHA-384, signer-id and Ed25519 (RFC 8032) is
// implemented. The ML-DSA (FIPS 204) crypto ops return `skipped`: the pinned SwiftDilithium 3.6.0
// exposes no seed-based (NIST ACVP xi) key derivation, so the deterministic seed->key path this
// contract needs cannot be produced with it (recorded as Unimplemented, never a false green).

import Foundation
import Naalp

// ---------------------------------------------------------------------------
// Minimal, deterministic JSON output model (avoids Foundation number/bool quirks)
// ---------------------------------------------------------------------------

indirect enum JOut {
    case s(String)
    case i(Int)
    case b(Bool)
    case arr([JOut])
    case obj([(String, JOut)])
}

func jsonEscape(_ s: String) -> String {
    var out = "\""
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                let hex = String(scalar.value, radix: 16)
                out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    out += "\""
    return out
}

func render(_ j: JOut) -> String {
    switch j {
    case .s(let v): return jsonEscape(v)
    case .i(let v): return String(v)
    case .b(let v): return v ? "true" : "false"
    case .arr(let items): return "[" + items.map(render).joined(separator: ",") + "]"
    case .obj(let pairs):
        return "{" + pairs.map { jsonEscape($0.0) + ":" + render($0.1) }.joined(separator: ",") + "}"
    }
}

func okOut(_ pairs: [(String, JOut)]) -> JOut { .obj([("out", .obj(pairs))]) }
func errOut(_ reason: String) -> JOut { .obj([("error", .s(reason))]) }
func skipOut(_ why: String) -> JOut { .obj([("skipped", .s(why))]) }

// ---------------------------------------------------------------------------
// Input helpers
// ---------------------------------------------------------------------------

func anyToUInt64(_ v: Any?) -> UInt64 {
    if let n = v as? NSNumber { return n.uint64Value }
    if let i = v as? Int { return UInt64(bitPattern: Int64(i)) }
    if let s = v as? String { return UInt64(s) ?? 0 }
    if let d = v as? Double { return UInt64(d) }
    return 0
}

func anyToInt(_ v: Any?) -> Int {
    if let n = v as? NSNumber { return n.intValue }
    if let i = v as? Int { return i }
    if let s = v as? String { return Int(s) ?? 0 }
    if let d = v as? Double { return Int(d) }
    return 0
}

func anyToBool(_ v: Any?) -> Bool {
    if let n = v as? NSNumber { return n.boolValue }
    if let b = v as? Bool { return b }
    return false
}

func anyToString(_ v: Any?, _ dflt: String = "") -> String {
    if let s = v as? String { return s }
    return dflt
}

let hexDigits = Array("0123456789abcdef")

func bytesToHex(_ b: [UInt8]) -> String {
    var s = ""
    s.reserveCapacity(b.count * 2)
    for x in b {
        s.append(hexDigits[Int(x >> 4)])
        s.append(hexDigits[Int(x & 0x0f)])
    }
    return s
}

func hexNibble(_ c: UInt8) throws -> UInt8 {
    switch c {
    case 0x30...0x39: return c - 0x30
    case 0x61...0x66: return c - 0x61 + 10
    case 0x41...0x46: return c - 0x41 + 10
    default: throw NaalpError("Malformed", "invalid hex digit")
    }
}

func hexToBytes(_ s: String) throws -> [UInt8] {
    let chars = Array(s.utf8)
    if chars.count % 2 != 0 { throw NaalpError("Malformed", "odd-length hex string") }
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
        let hi = try hexNibble(chars[i])
        let lo = try hexNibble(chars[i + 1])
        out.append((hi << 4) | lo)
        i += 2
    }
    return out
}

/// Hex-decode a required field.
func hx(_ inp: [String: Any], _ key: String) throws -> [UInt8] {
    guard let s = inp[key] as? String else {
        throw NaalpError("Malformed", "missing hex field \(key)")
    }
    return try hexToBytes(s)
}

// ---------------------------------------------------------------------------
// Tagged-value conversion for cbor.encode
// ---------------------------------------------------------------------------

func taggedToValue(_ v: Any?) throws -> CborValue {
    guard let arr = v as? [Any], arr.count == 2, let tag = arr[0] as? String else {
        throw NaalpError("Malformed", "tagged value must be [tag, payload]")
    }
    let payload = arr[1]
    switch tag {
    case "u":
        return .u(anyToUInt64(payload))
    case "b":
        guard let s = payload as? String else { throw NaalpError("Malformed", "b payload must be hex") }
        return .b(try hexToBytes(s))
    case "s":
        return .t(anyToString(payload))
    case "arr":
        guard let items = payload as? [Any] else { throw NaalpError("Malformed", "arr payload must be a list") }
        return .a(try items.map { try taggedToValue($0) })
    case "map":
        guard let pairs = payload as? [Any] else { throw NaalpError("Malformed", "map payload must be a list") }
        var out: [(CborValue, CborValue)] = []
        for p in pairs {
            guard let kv = p as? [Any], kv.count == 2 else {
                throw NaalpError("Malformed", "map entry must be [key, value]")
            }
            out.append((try taggedToValue(kv[0]), try taggedToValue(kv[1])))
        }
        return .m(out)
    default:
        throw NaalpError("Malformed", "unknown tag \(tag)")
    }
}

// ---------------------------------------------------------------------------
// Node / chunk parsing
// ---------------------------------------------------------------------------

func parseNodes(_ inp: [String: Any]) throws -> [Graph.Node] {
    guard let raw = inp["nodes"] as? [Any] else { throw NaalpError("Malformed", "missing nodes") }
    var nodes: [Graph.Node] = []
    for entry in raw {
        guard let n = entry as? [String: Any] else { throw NaalpError("Malformed", "node must be an object") }
        let id = try hexToBytes(anyToString(n["id_hex"]))
        let causesRaw = (n["causes_hex"] as? [Any]) ?? []
        let causes = try causesRaw.map { try hexToBytes(anyToString($0)) }
        let position = anyToInt(n["position"])
        nodes.append(Graph.Node(id: id, causes: causes, position: position))
    }
    return nodes
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

func errFrom(_ error: Error, _ fallbackKind: String) -> JOut {
    if let e = error as? NaalpError {
        return errOut("\(e.kind): \(e.message)")
    }
    return errOut("\(fallbackKind): \(error)")
}

func handle(_ op: String, _ inp: [String: Any]) -> JOut {
    do {
        switch op {
        case "sha384":
            return okOut([("digest_hex", .s(bytesToHex(Hashing.sha384(try hx(inp, "msg_hex")))))])

        case "cbor.encode":
            let v = try taggedToValue(inp["value"])
            return okOut([("bytes_hex", .s(bytesToHex(try Cbor.encode(v))))])

        case "cbor.decode":
            do {
                _ = try Cbor.decode(try hx(inp, "bytes_hex"))
                return okOut([("ok", .b(true))])
            } catch {
                return errFrom(error, "Malformed")
            }

        case "content.id":
            do {
                let v = try Cbor.decode(try hx(inp, "body_hex"))
                return okOut([("id_hex", .s(bytesToHex(try Cbor.contentId(v))))])
            } catch {
                return errFrom(error, "Malformed")
            }

        case "cose.tbs":
            let tbs = try Cose.toBeSignedRaw(try hx(inp, "protected_hex"), try hx(inp, "payload_hex"))
            return okOut([("tobesigned_hex", .s(bytesToHex(tbs)))])

        case "mldsa.keygen":
            return skipOut("no deterministic seed->key FIPS 204 path: SwiftDilithium 3.6.0 exposes no seed-based key derivation")

        case "ed25519.sign":
            let sig = try Cose.ed25519Sign(try hx(inp, "sk_hex"), try hx(inp, "msg_hex"))
            return okOut([("sig_hex", .s(bytesToHex(sig)))])

        case "cose.sign1":
            return skipOut("deterministic ML-DSA-from-seed unavailable in SwiftDilithium 3.6.0")

        case "cose.verify1":
            let alg = anyToInt(inp["alg"])
            if alg == Cose.ALG_ED25519 {
                let valid = try Cose.coseVerify1(alg, try hx(inp, "pubkey_hex"), try hx(inp, "obj_hex"))
                return okOut([("valid", .b(valid))])
            }
            return skipOut("ML-DSA verification unavailable in SwiftDilithium 3.6.0")

        case "signerid":
            do {
                let sid = try Identity.signerId(anyToInt(inp["alg"]), try hx(inp, "pubkey_hex"))
                return okOut([("signer_id", .s(sid))])
            } catch {
                return errFrom(error, "UnknownAlg")
            }

        case "nfc.check":
            do {
                let bytes = try hx(inp, "utf8_hex")
                guard let s = String(bytes: bytes, encoding: .utf8) else {
                    return errOut("NonNFC: input is not valid UTF-8")
                }
                try Identity.requireNFC(s)
                return okOut([("ok", .b(true))])
            } catch {
                return errFrom(error, "NonNFC")
            }

        case "effect.normalize":
            return okOut([("effect", .i(Policy.normalizeEffect(anyToInt(inp["value"]))))])

        case "effect.authorize":
            let ceiling = Policy.normalizeEffect(anyToInt(inp["granted"]))
            let allow = Policy.authorizes(ceiling, anyToInt(inp["effect"]))
            return okOut([("allow", .b(allow))])

        case "effect.safety_label":
            let bytes = try Policy.safetyLabelBytes(anyToString(inp["risk"]), anyToString(inp["scope"]))
            return okOut([("cbor_hex", .s(bytesToHex(bytes)))])

        case "approval.body":
            let body = try Records.approvalBody(try hx(inp, "approves_hex"), anyToString(inp["approver"]),
                                                anyToUInt64(inp["grant"]), try hx(inp, "nonce_hex"),
                                                anyToUInt64(inp["not_after"]))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "approval.id":
            let id = try Records.approvalId(try hx(inp, "approves_hex"), anyToString(inp["approver"]),
                                            anyToUInt64(inp["grant"]), try hx(inp, "nonce_hex"),
                                            anyToUInt64(inp["not_after"]))
            return okOut([("id_hex", .s(bytesToHex(id)))])

        case "ledger.entry":
            let body = try Records.ledgerEntry(anyToUInt64(inp["seq"]), try hx(inp, "prev_hex"),
                                               try hx(inp, "approval_id_hex"), anyToString(inp["by"]))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "receipt.body":
            let body = try Records.receiptBody(try hx(inp, "prev_hex"), try hx(inp, "obj_hex"),
                                               anyToUInt64(inp["seq"]), anyToUInt64(inp["at"]))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "receipt.head":
            return okOut([("head_hex", .s(bytesToHex(Records.receiptHead(try hx(inp, "body_hex")))))])

        case "causal.verify":
            do {
                try Graph.verifyCausal(try parseNodes(inp))
                return okOut([("valid", .b(true))])
            } catch {
                return errFrom(error, "CausalViolation")
            }

        case "delivery.update":
            let body = try Records.deliveryUpdate(try hx(inp, "obj_hex"), anyToUInt64(inp["stage"]), anyToUInt64(inp["at"]))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "stream.digest":
            guard let raw = inp["chunks"] as? [Any] else { throw NaalpError("Malformed", "missing chunks") }
            var chunks: [(offset: UInt64, data: [UInt8])] = []
            for c in raw {
                guard let cm = c as? [String: Any] else { throw NaalpError("Malformed", "chunk must be an object") }
                chunks.append((anyToUInt64(cm["offset"]), try hexToBytes(anyToString(cm["data_hex"]))))
            }
            return okOut([("digest_hex", .s(bytesToHex(Records.streamDigest(chunks))))])

        case "stream.open":
            var approval: [UInt8] = []
            if let ah = inp["approval_hex"] as? String, !ah.isEmpty {
                approval = try hexToBytes(ah)
            }
            let body = try Records.streamOpenBody(try hx(inp, "stream_id_hex"), anyToUInt64(inp["effect"]),
                                                  approval, anyToUInt64(inp["substream"]))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "stream.commit":
            let body = try Records.streamCommitBody(try hx(inp, "stream_id_hex"), try hx(inp, "digest_hex"))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "stream.checkpoint":
            let body = try Records.streamCheckpointBody(try hx(inp, "stream_id_hex"), anyToUInt64(inp["through_offset"]),
                                                        try hx(inp, "digest_so_far_hex"))
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "transport.emit":
            do {
                let result = try Records.transportEmit(anyToString(inp["transport"]),
                                                       anyToBool(inp["sensitive"]),
                                                       anyToBool(inp["require_peer_auth"]))
                return okOut([("result", .s(result))])
            } catch {
                return errFrom(error, "UnknownTransport")
            }

        case "carriage.body":
            do {
                let body = try Records.carriageBody(anyToUInt64(inp["protocol_id"]), anyToUInt64(inp["class"]),
                                                    anyToUInt64(inp["content_type"]), try hx(inp, "correlation_hex"),
                                                    anyToString(inp["method"]), try hx(inp, "foreign_hex"))
                return okOut([("body_hex", .s(bytesToHex(body)))])
            } catch {
                return errFrom(error, "MappingError")
            }

        case "channels.lookup":
            do {
                let (name, effect, variable) = try Channels.lookup(anyToInt(inp["channel"]), anyToInt(inp["kind"]))
                return okOut([("name", .s(name)), ("effect", .i(effect)), ("variable", .b(variable))])
            } catch {
                return errFrom(error, "UnknownKind")
            }

        case "channels.effect_check":
            do {
                try Channels.checkEffect(anyToInt(inp["channel"]), anyToInt(inp["kind"]), anyToInt(inp["effect"]))
                return okOut([("ok", .b(true))])
            } catch {
                return errFrom(error, "EffectDeclarationMismatch")
            }

        case "federation.reconcile":
            do {
                let order = try Graph.reconcile(try parseNodes(inp))
                return okOut([("order", .arr(order.map { .s(bytesToHex($0)) }))])
            } catch {
                return errFrom(error, "CausalViolation")
            }

        case "federation.record":
            let authorities = (inp["authorities"] as? [Any])?.map { anyToString($0) } ?? []
            let orderRaw = (inp["order"] as? [Any]) ?? []
            let order = try orderRaw.map { try hexToBytes(anyToString($0)) }
            let body = try Graph.reconcileRecord(authorities, order)
            return okOut([("body_hex", .s(bytesToHex(body)))])

        default:
            return skipOut("op not implemented: " + op)
        }
    } catch {
        return errFrom(error, "Malformed")
    }
}

// ---------------------------------------------------------------------------
// Wire loop: 4-byte little-endian length + UTF-8 JSON, both directions.
// ---------------------------------------------------------------------------

func readExact(_ fh: FileHandle, _ n: Int) -> Data? {
    var buf = Data()
    while buf.count < n {
        let chunk = fh.readData(ofLength: n - buf.count)
        if chunk.isEmpty {
            return buf.isEmpty ? nil : buf
        }
        buf.append(chunk)
    }
    return buf
}

func le32(_ n: UInt32) -> Data {
    return Data([
        UInt8(n & 0xff),
        UInt8((n >> 8) & 0xff),
        UInt8((n >> 16) & 0xff),
        UInt8((n >> 24) & 0xff),
    ])
}

func runLoop() {
    let stdin = FileHandle.standardInput
    let stdout = FileHandle.standardOutput
    while true {
        guard let lenData = readExact(stdin, 4), lenData.count == 4 else {
            return  // clean EOF
        }
        let bytes = [UInt8](lenData)
        let n = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
        guard let body = readExact(stdin, Int(n)), body.count == Int(n) else {
            return
        }

        var response: JOut
        if let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
            let op = obj["op"] as? String ?? ""
            let inp = (obj["in"] as? [String: Any]) ?? [:]
            response = handle(op, inp)
        } else {
            response = errOut("adapter exception: malformed request JSON")
        }

        let outBytes = Data(render(response).utf8)
        var frame = le32(UInt32(outBytes.count))
        frame.append(outBytes)
        stdout.write(frame)
    }
}

runLoop()
