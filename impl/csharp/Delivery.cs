// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Naalp
{
    /// <summary>
    /// C8 — delivery as four signed monotonic stages, the persist-before-acknowledge discipline, the
    /// live full-duplex switchboard, and the content-free relay (design.md §9; requirements
    /// R-9.1..9.4) — the C# SDK, ported from impl/go/delivery.
    ///
    /// <para>Delivery is four distinct, separately-observable stages, each a signed delivery.update
    /// naming the target object's content id and the stage reached — there is no single "sent"
    /// boolean (§9.1): persisted_origin -> accepted_relay -> persisted_target -> presented. A stage is
    /// advanced only after the object is durably persisted (WAL fsync), so a crash right after an
    /// acknowledgment loses nothing (§9.2). Observing a stage earlier than the one already reached is
    /// StageOutOfOrder (§9.4). The switchboard holds two connections open and passes objects through
    /// both directions concurrently (§9.3); a relay that holds objects only in transit writes an audit
    /// trail over content ids while retaining no payload (§9.4, R-9.4).</para>
    ///
    /// <para>The delivery.update body is deterministic CBOR built by the shared spine
    /// (<see cref="Records.DeliveryUpdate"/>); the content-id framing and the relay's audit trail reuse
    /// the shared <see cref="Cbor.ContentId"/> and <see cref="Audit"/> chain unchanged.</para>
    /// </summary>
    public static class Delivery
    {
        // Delivery stages (design.md §9.1), monotonic in this order.
        public const long StagePersistedOrigin = 0;
        public const long StageAcceptedRelay = 1;
        public const long StagePersistedTarget = 2;
        public const long StagePresented = 3;

        private static readonly string[] StageNames =
        {
            "persisted_origin", "accepted_relay", "persisted_target", "presented",
        };

        /// <summary>The name of a stage value (0..3), or "unknown".</summary>
        public static string StageName(long stage)
        {
            return (stage >= 0 && stage < StageNames.Length) ? StageNames[stage] : "unknown";
        }

        /// <summary>The T1 content-id framing multihash(0x20, 0x30, SHA-384(b)) used for relay receipts
        /// and delivery targets (the shared spine framing, §2.3).</summary>
        public static byte[] ContentId(byte[] b) => Cbor.ContentId(b);

        /// <summary>One signed delivery-stage notification (design.md §9.1).</summary>
        public sealed class DeliveryUpdate
        {
            public readonly byte[] Obj; // content id of the object whose delivery this reports
            public readonly long Stage; // the stage reached (0..3)
            public readonly long At;    // observer time, epoch ms

            public DeliveryUpdate(byte[] obj, long stage, long at)
            {
                Obj = obj;
                Stage = stage;
                At = at;
            }

            /// <summary>The deterministic-CBOR encoding {1: obj, 2: stage, 3: at} (shared spine).</summary>
            public byte[] Bytes() => Records.DeliveryUpdate(Obj, Stage, At);
        }

        /// <summary>Sign a delivery.update with the observer's key (a RAW deterministic ML-DSA signature
        /// over the update body, as the Go/Python references sign it).</summary>
        public static byte[] SignUpdate(DeliveryUpdate u, int alg, byte[] seed) => Cose.MldsaSign(alg, seed, u.Bytes());

        /// <summary>Verify a delivery.update signature under the observer's key.</summary>
        public static bool VerifyUpdate(DeliveryUpdate u, int alg, byte[] pubkey, byte[] sig)
            => Cose.MldsaVerify(alg, pubkey, u.Bytes(), sig);

        /// <summary>Open (creating if needed) a WAL-backed tracker and replay it to recover the last
        /// durable stage for every object.</summary>
        public static Tracker OpenTracker(string path) => new Tracker(path);

        /// <summary>
        /// A durable, per-object delivery-stage tracker enforcing monotonic stages and
        /// persist-before-acknowledge. Each Advance persists to the write-ahead log and fsyncs before
        /// returning the acknowledging update, so a crash after the ack loses nothing (§9.2).
        /// </summary>
        public sealed class Tracker : IDisposable
        {
            private readonly object _mu = new object();
            private readonly FileStream _f;
            private readonly Dictionary<string, long> _current = new Dictionary<string, long>(); // object-id -> highest stage reached

            internal Tracker(string path)
            {
                _f = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
                try
                {
                    Replay();
                }
                catch
                {
                    // A failed open (a Malformed/truncated WAL record) must not leak the exclusive
                    // FileShare.None handle: the constructor throws before the object is returned, so
                    // nothing can Dispose it, and on Windows the leaked handle blocks any later delete
                    // or replace of the WAL until GC finalizes the stream.
                    _f.Dispose();
                    throw;
                }
            }

            private void Replay()
            {
                _f.Seek(0, SeekOrigin.Begin);
                var lenBuf = new byte[4];
                while (true)
                {
                    if (!ReadFull(lenBuf))
                    {
                        break; // clean EOF
                    }
                    int n = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                    var rec = new byte[n];
                    if (!ReadFull(rec))
                    {
                        throw new NaalpException("Malformed", "truncated delivery WAL record");
                    }
                    DeliveryUpdate u = ParseUpdate(rec);
                    _current[Hex.Encode(u.Obj)] = u.Stage; // last durable stage wins (monotonic on write)
                }
                _f.Seek(0, SeekOrigin.End);
            }

            private bool ReadFull(byte[] buf)
            {
                int off = 0;
                while (off < buf.Length)
                {
                    int r = _f.Read(buf, off, buf.Length - off);
                    if (r == 0)
                    {
                        return off == 0 ? false : throw new NaalpException("Malformed", "truncated delivery WAL record");
                    }
                    off += r;
                }
                return true;
            }

            /// <summary>
            /// Record that obj reached stage at time at, and return the acknowledging update. A stage
            /// earlier than the one already reached is StageOutOfOrder (no state change); re-reporting
            /// the current stage is an idempotent no-op; a later stage is persisted (WAL fsync) before
            /// the update is returned. Skipping ahead is permitted; only regression is an error.
            /// </summary>
            public DeliveryUpdate Advance(byte[] obj, long stage, long at)
            {
                lock (_mu)
                {
                    string key = Hex.Encode(obj);
                    if (_current.TryGetValue(key, out long cur))
                    {
                        if (stage < cur)
                        {
                            throw new NaalpException("StageOutOfOrder", "a delivery stage regressed to an earlier stage");
                        }
                        if (stage == cur)
                        {
                            return new DeliveryUpdate((byte[])obj.Clone(), stage, at);
                        }
                    }
                    var u = new DeliveryUpdate((byte[])obj.Clone(), stage, at);
                    byte[] rec = u.Bytes();
                    var lenBuf = new byte[4];
                    lenBuf[0] = (byte)(rec.Length >> 24);
                    lenBuf[1] = (byte)(rec.Length >> 16);
                    lenBuf[2] = (byte)(rec.Length >> 8);
                    lenBuf[3] = (byte)rec.Length;
                    _f.Write(lenBuf, 0, 4);
                    _f.Write(rec, 0, rec.Length);
                    _f.Flush(flushToDisk: true); // persist-before-ack (R-9.2)
                    _current[key] = stage;
                    return u;
                }
            }

            /// <summary>The highest stage reached for obj and whether it has been seen.</summary>
            public (long Stage, bool Seen) Stage(byte[] obj)
            {
                lock (_mu)
                {
                    return _current.TryGetValue(Hex.Encode(obj), out long s) ? (s, true) : (0L, false);
                }
            }

            /// <summary>Flush and close the WAL file.</summary>
            public void Close()
            {
                lock (_mu)
                {
                    _f.Dispose();
                }
            }

            public void Dispose() => Close();
        }

        private static DeliveryUpdate ParseUpdate(byte[] rec)
        {
            if (!(Cbor.Decode(rec) is Cbor.M m))
            {
                throw new NaalpException("Malformed", "delivery update is not a map");
            }
            byte[]? obj = null;
            long? stage = null, at = null;
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U ku))
                {
                    throw new NaalpException("Malformed", "non-uint key");
                }
                switch (ku.V)
                {
                    case 1 when p.Val is Cbor.B b:
                        obj = b.V;
                        break;
                    case 2 when p.Val is Cbor.U s:
                        stage = s.V;
                        break;
                    case 3 when p.Val is Cbor.U a:
                        at = a.V;
                        break;
                    default:
                        throw new NaalpException("Malformed", "unknown or mistyped delivery-update field");
                }
            }
            if (obj == null || stage == null || at == null)
            {
                throw new NaalpException("Malformed", "delivery update is missing a field");
            }
            return new DeliveryUpdate(obj, stage.Value, at.Value);
        }

        /// <summary>One side of a switchboard connection: objects written to Send are relayed to the
        /// peer's Recv, concurrently with the reverse direction.</summary>
        public sealed class Endpoint
        {
            internal readonly BlockingCollection<byte[]> SendQ;
            internal readonly BlockingCollection<byte[]> RecvQ;

            internal Endpoint(int capacity)
            {
                SendQ = new BlockingCollection<byte[]>(capacity);
                RecvQ = new BlockingCollection<byte[]>(capacity);
            }

            /// <summary>Submit an object into the switchboard toward the peer.</summary>
            public void Send(byte[] obj) => SendQ.Add(obj);

            /// <summary>Receive the next object relayed from the peer (blocks until one arrives).</summary>
            public byte[] Recv() => RecvQ.Take();

            /// <summary>Receive the next relayed object, waiting at most timeoutMs; false on timeout.</summary>
            public bool TryRecv(int timeoutMs, out byte[]? obj) => RecvQ.TryTake(out obj, timeoutMs);
        }

        /// <summary>
        /// Holds two connections open and relays objects through in both directions concurrently
        /// (design.md §9.3) — a live full-duplex relay, not a one-object mailbox. Two pump tasks forward
        /// left->right and right->left simultaneously.
        /// </summary>
        public sealed class Switchboard
        {
            private readonly Endpoint _left;
            private readonly Endpoint _right;
            private readonly CancellationTokenSource _cts = new CancellationTokenSource();
            private readonly Task _pumpLR;
            private readonly Task _pumpRL;

            public Switchboard(int capacity)
            {
                _left = new Endpoint(capacity);
                _right = new Endpoint(capacity);
                // left.send -> right.recv, and right.send -> left.recv, concurrently.
                _pumpLR = Task.Run(() => Pump(_left.SendQ, _right.RecvQ, _cts.Token));
                _pumpRL = Task.Run(() => Pump(_right.SendQ, _left.RecvQ, _cts.Token));
            }

            private static void Pump(BlockingCollection<byte[]> inQ, BlockingCollection<byte[]> outQ, CancellationToken ct)
            {
                try
                {
                    foreach (byte[] obj in inQ.GetConsumingEnumerable(ct))
                    {
                        outQ.Add(obj, ct); // forwarded in transit; the pump retains nothing
                    }
                }
                catch (OperationCanceledException)
                {
                    // clean shutdown
                }
            }

            public Endpoint Left() => _left;
            public Endpoint Right() => _right;

            /// <summary>Stop both pumps and wait for them to exit.</summary>
            public void Close()
            {
                _cts.Cancel();
                try
                {
                    Task.WaitAll(_pumpLR, _pumpRL);
                }
                catch (AggregateException)
                {
                    // pumps exit via OperationCanceledException
                }
                _cts.Dispose();
            }
        }

        /// <summary>
        /// Routes objects while retaining no payload at rest: for each routed object it appends an audit
        /// receipt (§8) over the object's content id and returns the object for immediate forwarding,
        /// keeping only the receipt chain (content ids), never the payload (§9.4, R-9.4). The retained
        /// audit trail alone verifies as a valid chain.
        /// </summary>
        public sealed class ContentFreeRelay
        {
            private readonly Audit.Authority _auth;
            private readonly List<Audit.Receipt> _receipts = new List<Audit.Receipt>();
            private readonly List<byte[]> _sigs = new List<byte[]>();

            /// <summary>Make a relay whose audit trail is signed by the ML-DSA key derived from seed.</summary>
            public ContentFreeRelay(int alg, byte[] seed)
            {
                _auth = new Audit.Authority(alg, seed);
            }

            /// <summary>Record an audit receipt over obj's content id and return obj for forwarding. The
            /// relay keeps the receipt only; it does not store obj.</summary>
            public byte[] Route(byte[] obj, long at)
            {
                (Audit.Receipt rec, byte[] sig) = _auth.Append(ContentId(obj), at);
                _receipts.Add(rec);
                _sigs.Add(sig);
                return obj;
            }

            /// <summary>The receipts and signatures the relay retained (its only persistent state), for
            /// offline chain verification.</summary>
            public (List<Audit.Receipt> Receipts, List<byte[]> Sigs) AuditTrail() => (_receipts, _sigs);
        }
    }
}
