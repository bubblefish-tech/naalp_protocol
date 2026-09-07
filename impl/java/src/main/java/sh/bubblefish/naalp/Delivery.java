// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * N-AALP C8 delivery for the Java SDK — delivery as four signed monotonic stages, the
 * persist-before-acknowledge discipline, the live full-duplex switchboard, and the content-free relay
 * (design.md §9; R-9.1..9.4).
 *
 * <p>Delivery is four distinct, separately-observable stages, each a signed delivery.update naming the
 * target object's content id and the stage reached — there is no single "sent" boolean (§9.1):
 * persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is advanced only after
 * the object is durably persisted (WAL fsync), so a crash right after an acknowledgment loses nothing
 * (§9.2). Observing a stage earlier than the one already reached is StageOutOfOrder (§9.4). The
 * switchboard holds two connections open and passes objects through both directions concurrently
 * (§9.3); a relay that holds objects only in transit writes an audit trail over content ids while
 * retaining no payload (§9.4, R-9.4).
 *
 * <p>An independent transcription of impl/go/delivery (cross-checked against impl/python/naalp/delivery).
 * The delivery.update SIGNATURE is a RAW deterministic ML-DSA signature over the update body
 * ({@link Cose#mldsaSign}/{@link Cose#mldsaVerify}). The content-id framing and the relay's retained
 * trail reuse {@link Cbor} and {@link Audit}. Byte surfaces are graded against
 * vectors/delivery/cases.json; the WAL / switchboard / relay / signature are demonstrated in isolation.
 */
public final class Delivery {
    /** Delivery stages (design §9.1), monotonic in this order. */
    public static final long STAGE_PERSISTED_ORIGIN = 0;
    public static final long STAGE_ACCEPTED_RELAY = 1;
    public static final long STAGE_PERSISTED_TARGET = 2;
    public static final long STAGE_PRESENTED = 3;

    private static final String[] STAGE_NAMES = {
            "persisted_origin", "accepted_relay", "persisted_target", "presented"};

    private Delivery() {}

    /** The name of a stage value (0..3), or "unknown". */
    public static String stageName(long stage) {
        if (stage >= 0 && stage < STAGE_NAMES.length) {
            return STAGE_NAMES[(int) stage];
        }
        return "unknown";
    }

    /** T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets). */
    public static byte[] contentId(byte[] b) {
        return Cbor.contentId(b);
    }

    private static NaalpException stageOutOfOrder() {
        return new NaalpException("StageOutOfOrder", "a delivery stage regressed to an earlier stage");
    }

    private static NaalpException malformed(String why) {
        return new NaalpException("Malformed", why);
    }

    // ---- DeliveryUpdate: one signed delivery-stage notification (design §9.1) --------------------

    /** One signed delivery-stage notification. */
    public static final class DeliveryUpdate {
        public final byte[] obj; // content id of the object whose delivery this reports
        public final long stage; // the stage reached (0..3)
        public final long at;    // observer time, epoch ms

        public DeliveryUpdate(byte[] obj, long stage, long at) {
            this.obj = obj.clone();
            this.stage = stage;
            this.at = at;
        }

        /** Deterministic-CBOR encoding {1: obj, 2: stage, 3: at}. */
        public byte[] bytes() {
            return Cbor.encode(new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(obj)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(stage)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(at)))));
        }
    }

    /** Sign a delivery.update with the observer's key: a RAW deterministic signature over the body. */
    public static byte[] signUpdate(DeliveryUpdate u, int alg, byte[] seed) {
        return Cose.mldsaSign(alg, seed, u.bytes());
    }

    /** Verify a raw delivery.update signature under the observer's public key. */
    public static boolean verifyUpdate(DeliveryUpdate u, int alg, byte[] pk, byte[] sig) {
        return Cose.mldsaVerify(alg, pk, u.bytes(), sig);
    }

    private static DeliveryUpdate parseUpdate(byte[] rec) {
        Cbor.Value v;
        try {
            v = Cbor.decode(rec);
        } catch (NaalpException e) {
            throw malformed("delivery update is not canonical: " + e.kind);
        }
        if (!(v instanceof Cbor.M m)) {
            throw malformed("delivery update is not a map");
        }
        byte[] obj = null;
        Long stage = null;
        Long at = null;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U k)) {
                throw malformed("non-uint key");
            }
            if (k.v == 1 && p.val instanceof Cbor.B b) {
                obj = b.v;
            } else if (k.v == 2 && p.val instanceof Cbor.U s) {
                stage = s.v;
            } else if (k.v == 3 && p.val instanceof Cbor.U a) {
                at = a.v;
            } else {
                throw malformed("unknown or mistyped delivery-update field " + k.v);
            }
        }
        if (obj == null || stage == null || at == null) {
            throw malformed("delivery update missing a mandatory field");
        }
        return new DeliveryUpdate(obj, stage, at);
    }

    // ---- Tracker: durable, monotonic, persist-before-acknowledge (design §9.2) ------------------

    /** The (stage, seen) result of {@link Tracker#stage}. */
    public static final class StageResult {
        public final long stage;
        public final boolean seen;

        public StageResult(long stage, boolean seen) {
            this.stage = stage;
            this.seen = seen;
        }
    }

    /** A durable, per-object delivery-stage tracker enforcing monotonic stages and
     * persist-before-acknowledge. Each advance persists to the write-ahead log and fsyncs before
     * returning the acknowledging update, so a crash after the ack loses nothing (§9.2). WAL records
     * are length-prefixed (4-byte big-endian) deterministic-CBOR update bodies. */
    public static final class Tracker {
        private final RandomAccessFile raf;
        private final Map<String, Long> current = new HashMap<>();
        private final Object lock = new Object();

        private Tracker(RandomAccessFile raf) throws IOException {
            this.raf = raf;
            replay();
        }

        private static String key(byte[] obj) {
            return Hex.encode(obj);
        }

        private void replay() throws IOException {
            raf.seek(0);
            long len = raf.length();
            byte[] lenBuf = new byte[4];
            while (raf.getFilePointer() + 4 <= len) {
                raf.readFully(lenBuf);
                int n = ((lenBuf[0] & 0xFF) << 24) | ((lenBuf[1] & 0xFF) << 16)
                        | ((lenBuf[2] & 0xFF) << 8) | (lenBuf[3] & 0xFF);
                byte[] rec = new byte[n];
                raf.readFully(rec);
                DeliveryUpdate u = parseUpdate(rec);
                current.put(key(u.obj), u.stage); // last durable stage wins (monotonic on write)
            }
        }

        /** Record that obj reached stage at time at, returning the acknowledging update. A stage
         * earlier than the one already reached is StageOutOfOrder (no state change); re-reporting the
         * current stage is an idempotent no-op; a later stage is persisted (WAL fsync) before the update
         * is returned. Skipping ahead is permitted; only regression is an error. */
        public DeliveryUpdate advance(byte[] obj, long stage, long at) {
            synchronized (lock) {
                String k = key(obj);
                Long cur = current.get(k);
                if (cur != null) {
                    if (stage < cur) {
                        throw stageOutOfOrder();
                    }
                    if (stage == cur) {
                        return new DeliveryUpdate(obj, stage, at);
                    }
                }
                DeliveryUpdate u = new DeliveryUpdate(obj, stage, at);
                byte[] rec = u.bytes();
                byte[] lenBuf = {
                        (byte) (rec.length >>> 24), (byte) (rec.length >>> 16),
                        (byte) (rec.length >>> 8), (byte) rec.length};
                try {
                    raf.seek(raf.length());
                    raf.write(lenBuf);
                    raf.write(rec);
                    raf.getChannel().force(true); // persist-before-ack (R-9.2)
                } catch (IOException e) {
                    throw new NaalpException("IOError", e.toString());
                }
                current.put(k, stage);
                return u;
            }
        }

        /** The highest stage reached for obj and whether it has been seen. */
        public StageResult stage(byte[] obj) {
            synchronized (lock) {
                Long s = current.get(key(obj));
                return s != null ? new StageResult(s, true) : new StageResult(0, false);
            }
        }

        /** Flush and close the WAL file. */
        public void close() {
            synchronized (lock) {
                try {
                    raf.close();
                } catch (IOException e) {
                    throw new NaalpException("IOError", e.toString());
                }
            }
        }
    }

    /** Open (creating if needed) a WAL-backed tracker and replay it to recover the last durable stage
     * for every object. */
    public static Tracker openTracker(String path) {
        try {
            return new Tracker(new RandomAccessFile(path, "rw"));
        } catch (IOException e) {
            throw new NaalpException("IOError", e.toString());
        }
    }

    // ---- Switchboard: the live full-duplex relay (design §9.3) ----------------------------------

    private static final byte[] SENTINEL = new byte[0];

    /** One side of a switchboard connection: objects written to send are relayed to the peer's recv,
     * concurrently with the reverse direction. */
    public static final class Endpoint {
        private final BlockingQueue<byte[]> send;
        private final BlockingQueue<byte[]> recv;

        private Endpoint(BlockingQueue<byte[]> send, BlockingQueue<byte[]> recv) {
            this.send = send;
            this.recv = recv;
        }

        /** Submit an object into the switchboard toward the peer. */
        public void send(byte[] obj) {
            put(send, obj.clone());
        }

        /** Receive the next object relayed from the peer (blocks until one arrives). */
        public byte[] recv() {
            try {
                return recv.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new NaalpException("Interrupted", e.toString());
            }
        }
    }

    private static void put(BlockingQueue<byte[]> q, byte[] v) {
        try {
            q.put(v);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NaalpException("Interrupted", e.toString());
        }
    }

    /** Holds two connections open and relays objects through in both directions concurrently
     * (design §9.3) — a live full-duplex relay, not a one-object mailbox. Two pump threads forward
     * left->right and right->left simultaneously; a pump retains nothing (content-free in transit). */
    public static final class Switchboard {
        private final BlockingQueue<byte[]> lSend;
        private final BlockingQueue<byte[]> rSend;
        private final Endpoint left;
        private final Endpoint right;
        private final Thread t1;
        private final Thread t2;

        private Switchboard(int capacity) {
            int cap = Math.max(1, capacity);
            this.lSend = new LinkedBlockingQueue<>(cap);
            BlockingQueue<byte[]> lRecv = new LinkedBlockingQueue<>(cap);
            this.rSend = new LinkedBlockingQueue<>(cap);
            BlockingQueue<byte[]> rRecv = new LinkedBlockingQueue<>(cap);
            this.left = new Endpoint(lSend, lRecv);
            this.right = new Endpoint(rSend, rRecv);
            // left.send -> right.recv, and right.send -> left.recv, concurrently.
            this.t1 = new Thread(() -> pump(lSend, rRecv));
            this.t2 = new Thread(() -> pump(rSend, lRecv));
            t1.setDaemon(true);
            t2.setDaemon(true);
            t1.start();
            t2.start();
        }

        private void pump(BlockingQueue<byte[]> in, BlockingQueue<byte[]> out) {
            while (true) {
                byte[] obj;
                try {
                    obj = in.take();
                } catch (InterruptedException e) {
                    return;
                }
                if (obj == SENTINEL) {
                    return;
                }
                put(out, obj); // forwarded in transit; the pump retains nothing
            }
        }

        public Endpoint left() {
            return left;
        }

        public Endpoint right() {
            return right;
        }

        /** Stop both pumps and wait for them to exit. */
        public void close() {
            put(lSend, SENTINEL);
            put(rSend, SENTINEL);
            try {
                t1.join();
                t2.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Start a switchboard with per-direction buffering {@code capacity} and both pumps running. */
    public static Switchboard newSwitchboard(int capacity) {
        return new Switchboard(capacity);
    }

    // ---- ContentFreeRelay: routes objects while retaining no payload (design §9.4, R-9.4) --------

    /** The receipts and signatures a relay retained (its only persistent state). */
    public static final class Trail {
        public final List<Audit.Receipt> receipts;
        public final List<byte[]> sigs;

        public Trail(List<Audit.Receipt> receipts, List<byte[]> sigs) {
            this.receipts = receipts;
            this.sigs = sigs;
        }
    }

    /** Routes objects while retaining no payload at rest: for each routed object it appends a C7 audit
     * receipt over the object's content id and returns the object for immediate forwarding, keeping
     * only the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained audit trail
     * alone verifies as a valid chain. */
    public static final class ContentFreeRelay {
        private final Audit.Authority auth;
        private final List<Audit.Receipt> receipts = new ArrayList<>();
        private final List<byte[]> sigs = new ArrayList<>();

        private ContentFreeRelay(int alg, byte[] seed) {
            this.auth = new Audit.Authority(alg, seed);
        }

        /** Record an audit receipt over obj's content id and return obj for forwarding. The relay keeps
         * the receipt only; it does not store obj. */
        public byte[] route(byte[] obj, long at) {
            Audit.Signed s = auth.append(contentId(obj), at);
            receipts.add(s.receipt);
            sigs.add(s.sig);
            return obj.clone();
        }

        /** The receipts and signatures the relay retained, for offline chain verification. */
        public Trail auditTrail() {
            return new Trail(new ArrayList<>(receipts), new ArrayList<>(sigs));
        }
    }

    /** Make a relay whose audit trail is signed by the key derived from seed. */
    public static ContentFreeRelay newContentFreeRelay(int alg, byte[] seed) {
        return new ContentFreeRelay(alg, seed);
    }
}
