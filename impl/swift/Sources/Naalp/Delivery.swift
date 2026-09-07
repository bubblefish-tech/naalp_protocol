// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// N-AALP C8 delivery for the Swift SDK — delivery as four signed monotonic stages, the
// persist-before-acknowledge discipline, the concurrent full-duplex switchboard, and the content-free
// relay (design.md §9; R-9.1..9.4).
//
// Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
// target object's content id and the stage reached — there is no single "sent" boolean (§9.1):
// persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
// the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
// (§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
// switchboard holds two connections open and passes objects through both directions concurrently
// (§9.3); a relay that holds objects only in transit writes an audit trail over content ids while
// retaining no payload (§9.4, R-9.4).
//
// An independent transcription of impl/go/delivery (cross-read against impl/python/naalp/delivery.py),
// graded against the shared vectors/delivery/cases.json. The content-id framing and the relay's
// retained trail reuse the shared Naalp.Cbor and Naalp.Audit.
//
// CRYPTO SCOPE (PURE-ONLY): the corpus-graded surfaces (the four stage names, the delivery.update body
// byte-for-byte, the T1 content-id framing, and the durable WAL tracker replay) are pure. Swift cannot
// deterministically sign or verify ML-DSA (FIPS 204) with SwiftDilithium 3.6.0, so the reference's
// ML-DSA delivery.update signature is demonstrated with a real Ed25519 (RFC 8032) round-trip
// (signUpdate / verifyUpdate) exercised in isolation, NOT corpus-graded; the content-free relay's
// receipts are Ed25519-signed via the shared Audit.Authority. The reference's ML-DSA cross-language
// pins are NOT reproducible in the pure tier and are NOT fabricated (honest F2/F4), mirroring the PHP
// port.
//
// CONCURRENCY SCOPE: Swift on Linux has real OS threads, so the switchboard is a genuine concurrent
// full-duplex relay — two pump threads forward left->right and right->left simultaneously over
// bounded blocking queues, exactly as the Go reference's two pump goroutines.

import Crypto
import Foundation

public enum Delivery {

    // Delivery stages (§9.1), monotonic in this order.
    public static let STAGE_PERSISTED_ORIGIN: UInt64 = 0
    public static let STAGE_ACCEPTED_RELAY: UInt64 = 1
    public static let STAGE_PERSISTED_TARGET: UInt64 = 2
    public static let STAGE_PRESENTED: UInt64 = 3

    static let stageNames = ["persisted_origin", "accepted_relay", "persisted_target", "presented"]

    /// The name of a stage value (0..3), or "unknown".
    public static func stageName(_ stage: UInt64) -> String {
        return stage < UInt64(stageNames.count) ? stageNames[Int(stage)] : "unknown"
    }

    /// The T1 content-id framing multihash(0x20 sha2-384, 0x30 len-48) || SHA-384(bytes) (§2.3),
    /// identical to the spine framing (Naalp.Cbor.contentId over raw bytes).
    public static func contentId(_ b: [UInt8]) -> [UInt8] {
        return Cbor.contentId(b)
    }

    /// One signed delivery-stage notification (§9.1): `obj` is the content id of the object whose
    /// delivery this reports; `stage` is the stage reached (0..3); `at` is observer time, epoch ms.
    public struct DeliveryUpdate {
        public let obj: [UInt8]
        public let stage: UInt64
        public let at: UInt64
        public init(obj: [UInt8], stage: UInt64, at: UInt64) {
            self.obj = obj
            self.stage = stage
            self.at = at
        }

        /// Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}.
        public func bytes() throws -> [UInt8] {
            return try Cbor.encode(.m([
                (.u(1), .b(obj)),
                (.u(2), .u(stage)),
                (.u(3), .u(at)),
            ]))
        }
    }

    /// Sign a delivery.update with the observer's key. PURE-ONLY Swift: a real Ed25519 (RFC 8032)
    /// signature over the update body, standing in for the reference's ML-DSA signature.
    public static func signUpdate(_ update: DeliveryUpdate, _ seed: [UInt8]) throws -> [UInt8] {
        return try Cose.ed25519Sign(seed, try update.bytes())
    }

    /// Verify a raw Ed25519 delivery.update signature under the observer's public key.
    public static func verifyUpdate(_ update: DeliveryUpdate, _ pubkey: [UInt8], _ sig: [UInt8]) throws -> Bool {
        return Cose.ed25519Verify(pubkey, try update.bytes(), sig)
    }

    /// Reconstruct a DeliveryUpdate from a WAL record body; fail-closed (Malformed) on a non-canonical
    /// encoding, a non-map, a non-uint key, a mistyped/unknown field, or a missing mandatory field.
    public static func parseUpdate(_ rec: [UInt8]) throws -> DeliveryUpdate {
        let v: CborValue
        do {
            v = try Cbor.decode(rec)
        } catch {
            throw NaalpError("Malformed", "delivery update is not canonical")
        }
        guard case let .m(pairs) = v else {
            throw NaalpError("Malformed", "delivery update is not a map")
        }
        var obj: [UInt8]? = nil
        var stage: UInt64? = nil
        var at: UInt64? = nil
        for (k, val) in pairs {
            guard case let .u(kk) = k else {
                throw NaalpError("Malformed", "non-uint key")
            }
            switch kk {
            case 1:
                guard case let .b(b) = val else { throw NaalpError("Malformed", "obj not bstr") }
                obj = b
            case 2:
                guard case let .u(s) = val else { throw NaalpError("Malformed", "stage not uint") }
                stage = s
            case 3:
                guard case let .u(a) = val else { throw NaalpError("Malformed", "at not uint") }
                at = a
            default:
                throw NaalpError("Malformed", "unknown or mistyped delivery-update field")
            }
        }
        guard let o = obj, let s = stage, let a = at else {
            throw NaalpError("Malformed", "delivery update missing a mandatory field")
        }
        return DeliveryUpdate(obj: o, stage: s, at: a)
    }

    /// A durable, per-object delivery-stage tracker enforcing monotonic stages and
    /// persist-before-acknowledge. Each advance persists to the write-ahead log and fsyncs before
    /// returning the acknowledging update, so a crash after the ack loses nothing (§9.2). WAL records
    /// are length-prefixed (4-byte big-endian) deterministic-CBOR update bodies.
    public final class Tracker {
        private let handle: FileHandle
        private var current: [[UInt8]: UInt64] = [:] // object content id -> highest stage reached
        private let lock = NSLock()

        init(handle: FileHandle) throws {
            self.handle = handle
            try replay()
        }

        private func replay() throws {
            try handle.seek(toOffset: 0)
            while true {
                guard let lenBuf = try handle.read(upToCount: 4), !lenBuf.isEmpty else { break }
                if lenBuf.count != 4 {
                    throw NaalpError("Malformed", "truncated WAL length prefix")
                }
                let n = Int(lenBuf.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }) // big-endian
                guard let rec = try handle.read(upToCount: n), rec.count == n else {
                    throw NaalpError("Malformed", "truncated WAL record")
                }
                let u = try Delivery.parseUpdate(Array(rec))
                current[u.obj] = u.stage // last durable stage wins (monotonic on write)
            }
        }

        /// Record that obj reached stage at time at, returning the acknowledging update. A stage
        /// earlier than the one already reached is StageOutOfOrder (no state change); re-reporting the
        /// current stage is an idempotent no-op; a later stage is persisted (WAL fsync) before the
        /// update is returned. Skipping ahead is permitted; only regression is an error.
        public func advance(_ obj: [UInt8], _ stage: UInt64, _ at: UInt64) throws -> DeliveryUpdate {
            lock.lock()
            defer { lock.unlock() }
            if let cur = current[obj] {
                if stage < cur {
                    throw NaalpError("StageOutOfOrder", "a delivery stage regressed to an earlier stage")
                }
                if stage == cur {
                    return DeliveryUpdate(obj: obj, stage: stage, at: at)
                }
            }
            let u = DeliveryUpdate(obj: obj, stage: stage, at: at)
            let rec = try u.bytes()
            let n = UInt32(rec.count)
            let prefix: [UInt8] = [UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff),
                                   UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]
            _ = try handle.seekToEnd()
            try handle.write(contentsOf: Data(prefix + rec))
            try handle.synchronize() // persist-before-ack (R-9.2)
            current[obj] = stage
            return u
        }

        /// The highest stage reached for obj and whether it has been seen.
        public func stage(_ obj: [UInt8]) -> (UInt64, Bool) {
            lock.lock()
            defer { lock.unlock() }
            if let s = current[obj] {
                return (s, true)
            }
            return (0, false)
        }

        /// Flush and close the WAL file.
        public func close() throws {
            lock.lock()
            defer { lock.unlock() }
            try handle.close()
        }
    }

    /// Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable stage
    /// for every object.
    public static func openTracker(_ path: String) throws -> Tracker {
        let fm = FileManager.default
        if !fm.fileExists(atPath: path) {
            fm.createFile(atPath: path, contents: nil)
        }
        guard let h = FileHandle(forUpdatingAtPath: path) else {
            throw NaalpError("Malformed", "cannot open WAL at \(path)")
        }
        return try Tracker(handle: h)
    }

    /// A bounded, thread-safe blocking queue (an NSCondition-guarded FIFO) — the switchboard's
    /// per-direction transport. `put` blocks while full; `take` blocks while empty; `close` wakes all
    /// waiters and drains to EOF (nil).
    final class BlockingQueue {
        private let cond = NSCondition()
        private var items: [[UInt8]] = []
        private let capacity: Int
        private var closed = false

        init(_ capacity: Int) {
            self.capacity = Swift.max(1, capacity)
        }

        func put(_ x: [UInt8]) {
            cond.lock()
            defer { cond.unlock() }
            while items.count >= capacity && !closed {
                cond.wait()
            }
            if closed { return }
            items.append(x)
            cond.signal()
        }

        func take() -> [UInt8]? {
            cond.lock()
            defer { cond.unlock() }
            while items.isEmpty && !closed {
                cond.wait()
            }
            if items.isEmpty {
                return nil // closed and drained
            }
            let x = items.removeFirst()
            cond.signal()
            return x
        }

        func close() {
            cond.lock()
            closed = true
            cond.broadcast()
            cond.unlock()
        }
    }

    /// One side of a switchboard connection: objects written to `send` are relayed to the peer's
    /// `recv`, concurrently with the reverse direction.
    public final class Endpoint {
        let sendQ: BlockingQueue
        let recvQ: BlockingQueue
        init(send: BlockingQueue, recv: BlockingQueue) {
            self.sendQ = send
            self.recvQ = recv
        }

        /// Submit an object into the switchboard toward the peer.
        public func send(_ obj: [UInt8]) {
            sendQ.put(obj)
        }

        /// Receive the next object relayed from the peer (blocks until one arrives; returns [] once the
        /// switchboard is closed and drained).
        public func recv() -> [UInt8] {
            return recvQ.take() ?? []
        }
    }

    /// Holds two connections open and relays objects through in both directions concurrently
    /// (design §9.3) — a live full-duplex relay, not a one-object mailbox. Two pump threads forward
    /// left->right and right->left simultaneously; a pump retains nothing (content-free in transit).
    public final class Switchboard {
        private let leftEndpoint: Endpoint
        private let rightEndpoint: Endpoint
        private let queues: [BlockingQueue]
        private var threads: [Thread] = []

        public init(_ capacity: Int) {
            let lSend = BlockingQueue(capacity)
            let lRecv = BlockingQueue(capacity)
            let rSend = BlockingQueue(capacity)
            let rRecv = BlockingQueue(capacity)
            leftEndpoint = Endpoint(send: lSend, recv: lRecv)
            rightEndpoint = Endpoint(send: rSend, recv: rRecv)
            queues = [lSend, lRecv, rSend, rRecv]
            // left.send -> right.recv, and right.send -> left.recv, concurrently.
            let t1 = Thread { Switchboard.pump(lSend, rRecv) }
            let t2 = Thread { Switchboard.pump(rSend, lRecv) }
            t1.start()
            t2.start()
            threads = [t1, t2]
        }

        private static func pump(_ inQ: BlockingQueue, _ outQ: BlockingQueue) {
            while let obj = inQ.take() {
                outQ.put(obj) // forwarded in transit; the pump retains nothing
            }
        }

        /// The two endpoints of the switchboard.
        public func left() -> Endpoint { return leftEndpoint }
        public func right() -> Endpoint { return rightEndpoint }

        /// Stop both pumps (close every queue; each pump's take() then returns nil and the thread exits).
        public func close() {
            for q in queues {
                q.close()
            }
        }
    }

    /// Routes objects while retaining no payload at rest: for each routed object it appends a C7 audit
    /// receipt over the object's content id and returns the object for immediate forwarding, keeping
    /// only the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained audit trail
    /// alone verifies as a valid chain. PURE-ONLY Swift: the receipts are Ed25519-signed by the shared
    /// Audit.Authority.
    public final class ContentFreeRelay {
        private let auth: Audit.Authority
        private var receipts: [Audit.Receipt] = []
        private var sigs: [[UInt8]] = []

        public init(seed: [UInt8]) {
            self.auth = Audit.Authority(seed: seed)
        }

        /// Record an audit receipt over obj's content id and return obj for forwarding. The relay keeps
        /// the receipt only; it does not store obj.
        public func route(_ obj: [UInt8], _ at: UInt64) throws -> [UInt8] {
            let (rec, sig) = try auth.append(Delivery.contentId(obj), at)
            receipts.append(rec)
            sigs.append(sig)
            return obj
        }

        /// The receipts and signatures the relay retained (its only persistent state), for offline
        /// chain verification.
        public func auditTrail() -> ([Audit.Receipt], [[UInt8]]) {
            return (receipts, sigs)
        }
    }
}
