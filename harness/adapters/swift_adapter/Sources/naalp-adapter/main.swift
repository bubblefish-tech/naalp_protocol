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

/// Parse `in["nodes"]` as Federation.CausalNode (id + causes only — no position; federation
/// reconcile's tie-break is content id, never position, so position is not part of this shape).
func parseFederationNodes(_ inp: [String: Any]) throws -> [Federation.CausalNode] {
    guard let raw = inp["nodes"] as? [Any] else { throw NaalpError("Malformed", "missing nodes") }
    var nodes: [Federation.CausalNode] = []
    for entry in raw {
        guard let n = entry as? [String: Any] else { throw NaalpError("Malformed", "node must be an object") }
        let id = try hexToBytes(anyToString(n["id_hex"]))
        let causesRaw = (n["causes_hex"] as? [Any]) ?? []
        let causes = try causesRaw.map { try hexToBytes(anyToString($0)) }
        nodes.append(Federation.CausalNode(id: id, causes: causes))
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

/// The bare error kind (or "" for no error) — used by the {valid, error} state-machine cases, which
/// report the kind alone rather than the full "kind: message" adapter-error string.
func errKind(_ error: Error?) -> String {
    guard let error = error else { return "" }
    if let e = error as? NaalpError { return e.kind }
    return "\(error)"
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
            // The corpus names the parameter set with the string field `param` (like Go/Rust/Python).
            let kalg = anyToString(inp["param"]) == "ML-DSA-87" ? Cose.ALG_MLDSA87 : Cose.ALG_MLDSA65
            let pk = try MlDsa.keygenFromSeed(try hx(inp, "seed_hex"), kalg)
            return okOut([("pk_hex", .s(bytesToHex(pk)))])

        case "ed25519.sign":
            let sig = try Cose.ed25519Sign(try hx(inp, "sk_hex"), try hx(inp, "msg_hex"))
            return okOut([("sig_hex", .s(bytesToHex(sig)))])

        case "cose.sign1":
            let obj = try Cose.coseSign1(anyToInt(inp["alg"]), try hx(inp, "seed_hex"),
                                         try hx(inp, "protected_hex"), try hx(inp, "payload_hex"))
            return okOut([("obj_hex", .s(bytesToHex(obj)))])

        case "cose.verify1":
            let valid = try Cose.coseVerify1(anyToInt(inp["alg"]), try hx(inp, "pubkey_hex"), try hx(inp, "obj_hex"))
            return okOut([("valid", .b(valid))])

        // ---- opt-in LAMPS composite signature (alg -65537, design.md §4.2) ----
        case "composite.mprime":
            let mp = try Cose.computeMprime(Array("COMPSIG-MLDSA65-Ed25519-SHA512".utf8), [], try hx(inp, "m_hex"))
            return okOut([("mprime_hex", .s(bytesToHex(mp)))])

        case "composite.signerid":
            do {
                let sid = try Identity.compositeSignerId(anyToInt(inp["mldsa_alg"]), try hx(inp, "mldsa_pubkey_hex"), try hx(inp, "ed_pubkey_hex"))
                return okOut([("signer_id", .s(sid))])
            } catch {
                return errFrom(error, "UnknownAlg")
            }

        case "composite.sign":
            let value = try Cose.compositeSign(try hx(inp, "mldsa_seed_hex"), try hx(inp, "ed_seed_hex"), try hx(inp, "tbs_hex"))
            return okOut([("value_hex", .s(bytesToHex(value)))])

        case "composite.verify":
            let valid = try Cose.compositeVerify(try hx(inp, "mldsa_pubkey_hex"), try hx(inp, "ed_pubkey_hex"), try hx(inp, "m_hex"), try hx(inp, "sig_hex"))
            return okOut([("valid", .b(valid))])

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

        case "stream.state":
            // design.md §10 state table + § Timers (stream idle/commit timer): drive ONE stream through
            // an ordered `events` list on a fresh Guard; report the LAST event's outcome plus the
            // stream's final state. Graded against the independent, non-circular
            // tools/streamstate_oracle.py (F3). Mirrors impl/go's stream.state case.
            let rawEvents = (inp["events"] as? [Any]) ?? []
            let g = Streaming.newGuard()
            var lastErr: Error? = nil
            var lastStream: [UInt8] = []
            for re in rawEvents {
                guard let em = re as? [String: Any] else {
                    return errOut("Malformed: stream.state event is not an object")
                }
                let sid = try hx(em, "stream_hex")
                lastStream = sid
                switch anyToString(em["ev"]) {
                case "open":
                    let o = Streaming.StreamOpen(streamID: sid, effect: anyToUInt64(em["effect"]), approval: nil, substream: 0)
                    do { try g.open(o, anyToInt(em["granted"])); lastErr = nil } catch { lastErr = error }
                case "chunk":
                    do { try g.chunk(sid); lastErr = nil } catch { lastErr = error }
                case "checkpoint":
                    do { try g.checkpoint(sid); lastErr = nil } catch { lastErr = error }
                case "commit":
                    let rawChunks = (em["chunks"] as? [Any]) ?? []
                    var chunks: [Streaming.Chunk] = []
                    for rc in rawChunks {
                        guard let cm = rc as? [String: Any] else {
                            return errOut("Malformed: stream.state chunk is not an object")
                        }
                        chunks.append(Streaming.Chunk(offset: anyToUInt64(cm["offset"]),
                                                      data: try hexToBytes(anyToString(cm["data_hex"]))))
                    }
                    let digest = try hx(em, "digest_hex")
                    do {
                        try g.commit(Streaming.StreamCommit(streamID: sid, digest: digest), chunks)
                        lastErr = nil
                    } catch { lastErr = error }
                case "expire":
                    do { try g.expire(sid); lastErr = nil } catch { lastErr = error }
                default:
                    return errOut("Malformed: stream.state unknown event \(anyToString(em["ev"]))")
                }
            }
            let lastErrKind: String
            if let e = lastErr as? NaalpError { lastErrKind = e.kind } else { lastErrKind = "" }
            return okOut([
                ("valid", .b(lastErr == nil)),
                ("error", .s(lastErrKind)),
                ("state", .s(g.state(lastStream).name)),
            ])

        case "delivery.state":
            // ietf draft "## Delivery state machine" (# Object State Machines): drive ONE object
            // through an ordered `events` list of signed delivery updates on a fresh WAL-backed
            // Tracker; report the LAST event's outcome plus the object's final stage name. A
            // rejected event (regress -> StageOutOfOrder) leaves the recorded stage unchanged.
            // Graded against the independent, non-circular tools/delivery_state_oracle.py (F3).
            // Mirrors impl/go's delivery.state case.
            let rawEvents = (inp["events"] as? [Any]) ?? []
            let tmpPath = NSTemporaryDirectory() + "naalp-delivery-state-\(UUID().uuidString).wal"
            defer { try? FileManager.default.removeItem(atPath: tmpPath) }
            let tr = try Delivery.openTracker(tmpPath)
            defer { try? tr.close() }
            var lastErr: Error? = nil
            var lastObj: [UInt8] = []
            for re in rawEvents {
                guard let em = re as? [String: Any] else {
                    return errOut("Malformed: delivery.state event is not an object")
                }
                let obj = try hx(em, "obj_hex")
                lastObj = obj
                switch anyToString(em["ev"]) {
                case "update":
                    do { _ = try tr.advance(obj, anyToUInt64(em["stage"]), 0); lastErr = nil } catch { lastErr = error }
                default:
                    return errOut("Malformed: delivery.state unknown event \(anyToString(em["ev"]))")
                }
            }
            let (st, _) = tr.stage(lastObj)
            let lastErrKind: String
            if let e = lastErr as? NaalpError { lastErrKind = e.kind } else { lastErrKind = "" }
            return okOut([
                ("valid", .b(lastErr == nil)),
                ("error", .s(lastErrKind)),
                ("state", .s(Delivery.stageName(st))),
            ])

        case "approval.state":
            // ietf draft "## Approval state machine" (# Object State Machines): build ONE signed
            // approval, then drive it through an ordered `events` list of consume attempts through
            // the REAL composed choke point Approval.consumeApproval on a fresh single-use ledger;
            // report the LAST event's {valid, error} plus the ledger length after it (the draft's
            // "ledger left untouched by a rejected request", observable via Ledger.len()). Graded
            // against the independent, non-circular tools/approval_state_oracle.py (F3). The approver
            // key is a deterministic Ed25519 test key — the signature is verified, not graded (bytes
            // are not compared across ports for this op). Mirrors impl/go's approval.state case.
            guard let am = inp["approval"] as? [String: Any] else {
                return errOut("Malformed: approval.state missing approval object")
            }
            let a = Approval.ApprovalRecord(approves: try hx(am, "approves_hex"), approver: anyToString(am["approver"]),
                                            grant: anyToUInt64(am["grant"]), nonce: try hx(am, "nonce_hex"),
                                            notAfter: anyToUInt64(am["not_after"]))
            let seed = [UInt8](repeating: 0, count: 32) // deterministic all-zero test approver seed
            let pk = try Cose.ed25519PublicKey(seed)
            let sig = try Cose.ed25519Sign(seed, try a.bytes())
            let verify: Approval.Verify = { msg, s in Cose.ed25519Verify(pk, msg, s) }

            let tmpPath = NSTemporaryDirectory() + "naalp-approval-state-\(UUID().uuidString).wal"
            defer { try? FileManager.default.removeItem(atPath: tmpPath) }
            let ledger = try Approval.Ledger.open(tmpPath)
            defer { try? ledger.close() }

            let rawApprovalEvents = (inp["events"] as? [Any]) ?? []
            var lastApprovalErr: Error? = nil
            for re in rawApprovalEvents {
                guard let em = re as? [String: Any] else {
                    return errOut("Malformed: approval.state event is not an object")
                }
                switch anyToString(em["ev"]) {
                case "consume":
                    let presentCID = try hx(em, "present_cid_hex")
                    do {
                        _ = try Approval.consumeApproval(a, verify, sig, presentCID, anyToUInt64(em["pos_time"]),
                                                         anyToInt(em["required_effect"]), ledger, anyToString(em["by"]))
                        lastApprovalErr = nil
                    } catch { lastApprovalErr = error }
                default:
                    return errOut("Malformed: approval.state unknown event \(anyToString(em["ev"]))")
                }
            }
            let lastApprovalErrKind: String
            if let e = lastApprovalErr as? NaalpError { lastApprovalErrKind = e.kind } else { lastApprovalErrKind = "" }
            return okOut([
                ("valid", .b(lastApprovalErr == nil)),
                ("error", .s(lastApprovalErrKind)),
                ("ledger_len", .i(ledger.len())),
            ])

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

        case "reconcile.state":
            // ietf draft "## Reconcile state machine" (# Object State Machines): drive the machine
            // through ONE event (add-chain | linearize | verify) on fresh state and report
            // {valid, error}. add-chain runs the draft's fixed VerifyChain-then-Observe pipeline (a
            // `chain` that must independently pass VerifyChain, plus an optional `extra` receipt fed
            // only to Observe -- a chain array cannot itself carry a duplicate seq without
            // independently tripping ChainBroken, so equivocation is exercised via the separate
            // `extra` observation); linearize runs Federation.reconcile (which calls
            // Graph.verifyCausal internally); verify runs Federation.verifyReconcileOrder, which MUST
            // recompute via reconcile (content-id tie-break), never a position tie-break. Graded
            // against the independent, non-circular tools/reconcile_state_oracle.py (F3). The
            // authority key is a deterministic all-zero Ed25519 test seed -- the signature is
            // verified, not graded (bytes are not compared across ports for this op). Note:
            // Audit.Auditor.observe RETURNS a ForkProof on equivocation rather than throwing, so a
            // non-nil return is treated as the Equivocation outcome here. Mirrors impl/go's
            // reconcile.state case.
            let seed = [UInt8](repeating: 0, count: 32) // deterministic all-zero test authority seed
            let signerID = try Cose.ed25519PublicKey(seed)
            let verify: Audit.Verify = { msg, sig in Cose.ed25519Verify(signerID, msg, sig) }

            func buildReceipt(_ rm: [String: Any]) throws -> Audit.Receipt {
                return Audit.Receipt(prev: try hx(rm, "prev_hex"), obj: try hx(rm, "obj_hex"),
                                     seq: anyToUInt64(rm["seq"]), at: anyToUInt64(rm["at"]))
            }

            switch anyToString(inp["event"]) {
            case "add-chain":
                let rawChain = (inp["chain"] as? [Any]) ?? []
                var receipts: [Audit.Receipt] = []
                var sigs: [[UInt8]] = []
                for rc in rawChain {
                    guard let rm = rc as? [String: Any] else {
                        return errOut("Malformed: reconcile.state chain entry is not an object")
                    }
                    let r = try buildReceipt(rm)
                    receipts.append(r)
                    sigs.append(try Cose.ed25519Sign(seed, try r.bytes()))
                }
                if let ci = inp["corrupt_sig_at"] as? NSNumber {
                    let idx = ci.intValue
                    var corrupted = sigs[idx]
                    corrupted[0] ^= 0xFF
                    sigs[idx] = corrupted
                }
                var lastErr: Error? = nil
                do {
                    try Audit.verifyChain(receipts, sigs, verify)
                } catch {
                    lastErr = error
                }
                if lastErr == nil {
                    let auditor = Audit.Auditor(verify: verify, signer: signerID)
                    for (i, r) in receipts.enumerated() {
                        do {
                            if try auditor.observe(r, sigs[i]) != nil {
                                lastErr = NaalpError("Equivocation", "auditor detected equivocation")
                                break
                            }
                        } catch {
                            lastErr = error
                            break
                        }
                    }
                    if lastErr == nil, let em = inp["extra"] as? [String: Any] {
                        let er = try buildReceipt(em)
                        let esig = try Cose.ed25519Sign(seed, try er.bytes())
                        do {
                            if try auditor.observe(er, esig) != nil {
                                lastErr = NaalpError("Equivocation", "auditor detected equivocation")
                            }
                        } catch {
                            lastErr = error
                        }
                    }
                }
                return okOut([("valid", .b(lastErr == nil)), ("error", .s(errKind(lastErr)))])

            case "linearize":
                let nodes = try parseFederationNodes(inp)
                var lastErr: Error? = nil
                do { _ = try Federation.reconcile(nodes) } catch { lastErr = error }
                return okOut([("valid", .b(lastErr == nil)), ("error", .s(errKind(lastErr)))])

            case "verify":
                let nodes = try parseFederationNodes(inp)
                let rawOrder = (inp["claimed_order_hex"] as? [Any]) ?? []
                let order = try rawOrder.map { try hexToBytes(anyToString($0)) }
                let rec = Federation.ReconcileRecord(authorities: [], order: order)
                var lastErr: Error? = nil
                do { try Federation.verifyReconcileOrder(rec, nodes) } catch { lastErr = error }
                return okOut([("valid", .b(lastErr == nil)), ("error", .s(errKind(lastErr)))])

            default:
                return errOut("Malformed: reconcile.state unknown event \(anyToString(inp["event"]))")
            }

        // ---- R7 decoder resource bounds: decode + bound-enforce an untrusted object; all four
        // object-level bounds (DepthExceeded, TooManyCauses, TooManyExtensions) fire BEFORE the
        // COSE signature is checked, so no real key/alg is ever consulted -- a permissive kind
        // validator + an unused alg/pubkey pair is enough. over_size materializes the octet-size
        // bound (rejected on raw length before any parse). Mirrors impl/go's object.decode case.
        case "object.decode":
            var obj: [UInt8]
            if let overSizeRaw = inp["over_size"] {
                obj = [UInt8](repeating: 0, count: anyToInt(overSizeRaw))
            } else {
                obj = try hx(inp, "obj_hex")
            }
            let kindOK: KindValidator = { _, _ in true }
            do {
                _ = try Envelope.verify(1, Cose.ALG_MLDSA65, [], kindOK, obj)
                return okOut([("valid", .b(true)), ("error", .s(""))])
            } catch let e as NaalpError {
                return okOut([("valid", .b(false)), ("error", .s(e.kind))])
            } catch {
                return okOut([("valid", .b(false)), ("error", .s("Malformed"))])
            }

        // ---- R7 decoder resource bounds: the stream chunk-count bound fires before the digest
        // check, so a zero/default commitment is enough -- n empty chunks against an empty
        // StreamCommit. Mirrors impl/go's stream.verify_commit case.
        case "stream.verify_commit":
            let n = anyToInt(inp["chunk_count"])
            let chunks = (0..<max(0, n)).map { _ in Streaming.Chunk(offset: 0, data: []) }
            let commit = Streaming.StreamCommit(streamID: [], digest: [])
            do {
                try Streaming.verifyCommit(commit, chunks)
                return okOut([("valid", .b(true)), ("error", .s(""))])
            } catch let e as NaalpError {
                return okOut([("valid", .b(false)), ("error", .s(e.kind))])
            } catch {
                return okOut([("valid", .b(false)), ("error", .s("Malformed"))])
            }

        case "error.name_for_code":
            // T3.3: the naalp-error registry table lookup (design.md §3.5). Grades the port's
            // embedded 119-entry name<->code table per-code, plus the unknown-code (opaque)
            // contract. Mirrors impl/go's error.name_for_code case.
            let (name, reg) = Naalperror.nameForCode(anyToUInt64(inp["code"]))
            return okOut([("name", .s(name)), ("registered", .b(reg))])

        case "error.encode":
            // T3.3: deterministic CBOR of a naalp-error body {1:code, 2:name, ?3:detail,
            // ?4:subject}. Mirrors impl/go's error.encode case.
            var subj: [UInt8]? = nil
            if inp["subject_hex"] != nil {
                subj = try hx(inp, "subject_hex")
            }
            let detail = anyToString(inp["detail"])
            let name = anyToString(inp["name"])
            let body = try Naalperror.encode(anyToUInt64(inp["code"]), name, detail, subj)
            return okOut([("body_hex", .s(bytesToHex(body)))])

        case "error.decode":
            // T3.3: parse + dual-carriage validate a naalp-error body (registered code + wrong
            // name -> Malformed; unknown code -> opaque accept). Mirrors impl/go's error.decode
            // case.
            let body = try hx(inp, "body_hex")
            do {
                let eo = try Naalperror.decode(body)
                return okOut([("valid", .b(true)), ("code", .i(Int(eo.code))), ("name", .s(eo.name))])
            } catch let e as NaalpError {
                return okOut([("valid", .b(false)), ("error", .s(e.kind))])
            } catch {
                return okOut([("valid", .b(false)), ("error", .s("Malformed"))])
            }

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
