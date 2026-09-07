// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

import java.io.RandomAccessFile
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue

/**
 * C8 delivery for the Kotlin SDK — delivery as four signed monotonic stages, the
 * persist-before-acknowledge discipline, the live full-duplex switchboard, and the content-free
 * relay (design.md §9; R-9.1..9.4).
 *
 * Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
 * target object's content id and the stage reached — there is no single "sent" boolean (§9.1):
 * persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
 * the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
 * (§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
 * switchboard holds two connections open and passes objects through both directions concurrently
 * (§9.3); a relay that holds objects only in transit writes an audit trail over content ids while
 * retaining no payload (§9.4, R-9.4).
 *
 * Ported from impl/go/delivery (cross-read against impl/python/naalp/delivery.py). The delivery.update
 * signature is a RAW deterministic ML-DSA signature over the update body (Cose.mldsaSign /
 * Cose.mldsaVerify). The content-id framing and the relay's retained trail reuse the shared Cbor and
 * Audit. Graded against the shared vectors/delivery/cases.json.
 */
object Delivery {

    // Delivery stages (design §9.1), monotonic in this order.
    const val STAGE_PERSISTED_ORIGIN = 0L
    const val STAGE_ACCEPTED_RELAY = 1L
    const val STAGE_PERSISTED_TARGET = 2L
    const val STAGE_PRESENTED = 3L

    private val STAGE_NAMES = arrayOf("persisted_origin", "accepted_relay", "persisted_target", "presented")

    /** The name of a stage value (0..3), or "unknown". */
    fun stageName(stage: Long): String =
        if (stage in 0 until STAGE_NAMES.size.toLong()) STAGE_NAMES[stage.toInt()] else "unknown"

    /** T1 content-id framing multihash(0x20, SHA-384(b)) — identical to the spine framing (§2.3). */
    fun contentId(b: ByteArray): ByteArray = Cbor.contentId(b)

    /** One signed delivery-stage notification (design §9.1). */
    class DeliveryUpdate(obj: ByteArray, val stage: Long, val at: Long) {
        /** content id of the object whose delivery this reports. */
        val obj: ByteArray = obj.copyOf()

        /** Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}. */
        fun bytes(): ByteArray = Cbor.encode(
            Cbor.M(
                listOf(
                    Cbor.Pair(Cbor.U(1), Cbor.B(obj)),
                    Cbor.Pair(Cbor.U(2), Cbor.U(stage)),
                    Cbor.Pair(Cbor.U(3), Cbor.U(at)),
                )
            )
        )
    }

    /** Sign a delivery.update with the observer's key: a RAW deterministic signature over the body. */
    fun signUpdate(update: DeliveryUpdate, alg: Int, seed: ByteArray): ByteArray =
        Cose.mldsaSign(alg, seed, update.bytes())

    /** Verify a raw delivery.update signature under the observer's public key. */
    fun verifyUpdate(update: DeliveryUpdate, alg: Int, pubkey: ByteArray, sig: ByteArray): Boolean =
        Cose.mldsaVerify(alg, pubkey, update.bytes(), sig)

    /** Reconstruct a DeliveryUpdate from a WAL record body; fail-closed on a malformed shape. */
    private fun parseUpdate(rec: ByteArray): DeliveryUpdate {
        val v = Cbor.decode(rec)
        if (v !is Cbor.M) throw NaalpException("Malformed", "delivery update is not a map")
        var obj: ByteArray? = null
        var stage: Long? = null
        var at: Long? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("Malformed", "non-uint key")
            when (k.v) {
                1L -> if (p.v is Cbor.B) obj = (p.v as Cbor.B).v else throw NaalpException("Malformed", "obj not bstr")
                2L -> if (p.v is Cbor.U) stage = (p.v as Cbor.U).v else throw NaalpException("Malformed", "stage not uint")
                3L -> if (p.v is Cbor.U) at = (p.v as Cbor.U).v else throw NaalpException("Malformed", "at not uint")
                else -> throw NaalpException("Malformed", "unknown delivery-update key")
            }
        }
        if (obj == null || stage == null || at == null) {
            throw NaalpException("Malformed", "delivery update missing a mandatory field")
        }
        return DeliveryUpdate(obj, stage, at)
    }

    /**
     * A durable, per-object delivery-stage tracker enforcing monotonic stages and
     * persist-before-acknowledge. Each advance persists to the write-ahead log and fsyncs before
     * returning the acknowledging update, so a crash after the ack loses nothing (§9.2). WAL records
     * are length-prefixed (4-byte big-endian) deterministic-CBOR update bodies.
     */
    class Tracker internal constructor(private val raf: RandomAccessFile) {
        private val lock = Any()
        private val current = HashMap<String, Long>() // object-id (hex) -> highest stage reached

        init {
            replay()
        }

        private fun replay() {
            raf.seek(0)
            val lenBuf = ByteArray(4)
            while (true) {
                val n = raf.read(lenBuf)
                if (n == -1) break
                if (n != 4) throw NaalpException("Malformed", "truncated WAL length prefix")
                val len = ((lenBuf[0].toInt() and 0xFF) shl 24) or
                    ((lenBuf[1].toInt() and 0xFF) shl 16) or
                    ((lenBuf[2].toInt() and 0xFF) shl 8) or
                    (lenBuf[3].toInt() and 0xFF)
                val rec = ByteArray(len)
                raf.readFully(rec)
                val u = parseUpdate(rec)
                current[keyOf(u.obj)] = u.stage // last durable stage wins (monotonic on write)
            }
        }

        /**
         * Record that obj reached stage at time at, returning the acknowledging update. A stage
         * earlier than the one already reached is StageOutOfOrder (no state change); re-reporting the
         * current stage is an idempotent no-op; a later stage is persisted (WAL fsync) before the
         * update is returned. Skipping ahead is permitted; only regression is an error.
         */
        fun advance(obj: ByteArray, stage: Long, at: Long): DeliveryUpdate {
            synchronized(lock) {
                val key = keyOf(obj)
                val cur = current[key]
                if (cur != null) {
                    if (stage < cur) throw NaalpException("StageOutOfOrder", "a delivery stage regressed to an earlier stage")
                    if (stage == cur) return DeliveryUpdate(obj, stage, at)
                }
                val u = DeliveryUpdate(obj, stage, at)
                val rec = u.bytes()
                val lenBuf = byteArrayOf(
                    (rec.size ushr 24).toByte(), (rec.size ushr 16).toByte(),
                    (rec.size ushr 8).toByte(), rec.size.toByte(),
                )
                raf.seek(raf.length())
                raf.write(lenBuf)
                raf.write(rec)
                raf.fd.sync() // persist-before-ack (R-9.2)
                current[key] = stage
                return u
            }
        }

        /** The highest stage reached for obj and whether it has been seen. */
        fun stage(obj: ByteArray): Pair<Long, Boolean> {
            synchronized(lock) {
                val s = current[keyOf(obj)]
                return if (s != null) Pair(s, true) else Pair(0L, false)
            }
        }

        /** Flush and close the WAL file. */
        fun close() {
            synchronized(lock) { raf.close() }
        }

        private fun keyOf(b: ByteArray): String = Hex.encode(b)
    }

    /**
     * Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable stage
     * for every object.
     */
    fun openTracker(path: String): Tracker = Tracker(RandomAccessFile(path, "rw"))

    /**
     * One side of a switchboard connection: objects written to send are relayed to the peer's recv,
     * concurrently with the reverse direction.
     */
    class Endpoint internal constructor(private val sendQ: BlockingQueue<ByteArray>, private val recvQ: BlockingQueue<ByteArray>) {
        /** Submit an object into the switchboard toward the peer. */
        fun send(obj: ByteArray) = sendQ.put(obj.copyOf())

        /** Receive the next object relayed from the peer (blocks until one arrives). */
        fun recv(): ByteArray = recvQ.take()
    }

    /**
     * Holds two connections open and relays objects through in both directions concurrently (§9.3) —
     * a live full-duplex relay, not a one-object mailbox. Two pump threads forward left->right and
     * right->left simultaneously; a pump retains nothing (content-free in transit).
     */
    class Switchboard(capacity: Int) {
        private val sentinel = ByteArray(0)
        private val lSend: BlockingQueue<ByteArray> = ArrayBlockingQueue(capacity)
        private val lRecv: BlockingQueue<ByteArray> = ArrayBlockingQueue(capacity)
        private val rSend: BlockingQueue<ByteArray> = ArrayBlockingQueue(capacity)
        private val rRecv: BlockingQueue<ByteArray> = ArrayBlockingQueue(capacity)
        private val leftEp = Endpoint(lSend, lRecv)
        private val rightEp = Endpoint(rSend, rRecv)
        private val t1: Thread
        private val t2: Thread

        init {
            // left.send -> right.recv, and right.send -> left.recv, concurrently.
            t1 = Thread { pump(lSend, rRecv) }.apply { isDaemon = true; start() }
            t2 = Thread { pump(rSend, lRecv) }.apply { isDaemon = true; start() }
        }

        private fun pump(inQ: BlockingQueue<ByteArray>, outQ: BlockingQueue<ByteArray>) {
            while (true) {
                val obj = inQ.take()
                if (obj === sentinel) return
                outQ.put(obj) // forwarded in transit; the pump retains nothing
            }
        }

        fun left(): Endpoint = leftEp
        fun right(): Endpoint = rightEp

        /** Stop both pumps and wait for them to exit. */
        fun close() {
            lSend.put(sentinel)
            rSend.put(sentinel)
            t1.join()
            t2.join()
        }
    }

    /**
     * Routes objects while retaining no payload at rest: for each routed object it appends a C7 audit
     * receipt over the object's content id and returns the object for immediate forwarding, keeping
     * only the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained audit trail
     * alone verifies as a valid chain.
     */
    class ContentFreeRelay(alg: Int, seed: ByteArray) {
        private val auth = Audit.Authority(alg, seed)
        private val receipts = ArrayList<Audit.Receipt>()
        private val sigs = ArrayList<ByteArray>()

        /**
         * Record an audit receipt over obj's content id and return obj for forwarding. The relay keeps
         * the receipt only; it does not store obj.
         */
        fun route(obj: ByteArray, at: Long): ByteArray {
            val (rec, sig) = auth.append(contentId(obj), at)
            receipts.add(rec)
            sigs.add(sig)
            return obj.copyOf()
        }

        /**
         * The receipts and signatures the relay retained (its only persistent state), for offline
         * chain verification.
         */
        fun auditTrail(): Pair<List<Audit.Receipt>, List<ByteArray>> = Pair(receipts.toList(), sigs.toList())
    }
}
