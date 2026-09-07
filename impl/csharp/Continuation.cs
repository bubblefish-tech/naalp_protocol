// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C17 — N-AALP-CONT flow continuation (design.md §20; R-CONT-1..7) — the C# SDK, ported from
    /// impl/go/continuation and cross-checked against impl/python/naalp/continuation and the Java/Kotlin
    /// ports.
    ///
    /// <para>N-AALP-CONT generalizes native streaming (one signed StreamOpen, cheap per-chunk data, one
    /// signed StreamCommit over a rolling digest) into a domain-agnostic flow:</para>
    /// <list type="bullet">
    ///   <item><see cref="FlowOpen"/> is the ONE full ML-DSA signature that fixes the flow's authority:
    ///   its flow_id, its effect ceiling, and the content-ids of the approvals that authorize it up to
    ///   that ceiling. The authority is reconstructable from the FlowOpen bytes ALONE
    ///   (<see cref="ParseFlowOpen"/>) — no session or server state.</item>
    ///   <item>A <see cref="Continuation"/> (this outer type) is a CHEAP object: no per-object
    ///   signature, only a SHA-384 hash-chain link. Each link's head is SHA-384(link body); its
    ///   <c>Prev</c> is the previous link's head; the genesis prev is the FlowOpen's head. A link carries
    ///   its own effect, which MUST stay at or below the ceiling (AboveCeiling otherwise — the cheap path
    ///   can never escalate past the one full signature + approval).</item>
    ///   <item><see cref="Checkpoint"/> confirms a contiguous prefix and DETECTS A GAP (GapDetected).</item>
    ///   <item><see cref="FlowCommit"/> is a second full ML-DSA signature binding the whole ordered
    ///   sequence with ONE signature regardless of the number of continuations.</item>
    /// </list>
    ///
    /// <para>Domain separation is structural: FlowOpen (3 fields), Continuation (5 fields), Checkpoint
    /// (3 fields, a bstr head at 3) and FlowCommit (2 fields) are each a distinct deterministic-CBOR
    /// shape. Byte surfaces are graded against vectors/continuation/cases.json; the FlowOpen / FlowCommit
    /// signatures are real deterministic ML-DSA-65 (COSE_Sign1), demonstrated in isolation (the corpus
    /// carries no signature vector for this channel).</para>
    ///
    /// <para>u64 note: a through_seq / seq at or above 2^63 has no positive <c>long</c> representation.
    /// The shared C# deterministic-CBOR encoder (like the Go/Java/Kotlin references) refuses to emit a
    /// negative uint, so a &gt;=2^63 value is only ever RECEIVED and decoded, never legitimately emitted
    /// by the shortest-form encoder; the u64::MAX overflow checkpoint is therefore DECODE-graded (the
    /// decoded through_seq round-trips as u64::MAX) and behaviour-graded (GapDetected), exactly as the
    /// Java/Kotlin ports grade it. A seq below 2^63 (e.g. the 0x0102030405060708 big-seq vector)
    /// round-trips byte-exact on both encode and decode.</para>
    /// </summary>
    public sealed class Continuation
    {
        /// <summary>The width of a chain head / prev link (SHA-384 = 48 bytes). A FlowOpen head anchors a chain.</summary>
        public const int HeadSize = 48;

        // ---- the cheap Continuation link (design §20.3) — the outer instance type ------------------

        public readonly byte[] FlowOpenId; // the originating FlowOpen's content-id (WrongFlow if it mismatches)
        public readonly long Seq;          // 0-based position in the chain
        public readonly long Effect;       // this step's effect; MUST be <= the FlowOpen ceiling (AboveCeiling otherwise)
        public readonly byte[] PayloadId;  // content-id of this step's payload
        public readonly byte[] Prev;       // the previous link's head (the FlowOpen head for seq 0)

        public Continuation(byte[] flowOpenId, long seq, long effect, byte[] payloadId, byte[] prev)
        {
            FlowOpenId = (byte[])flowOpenId.Clone();
            Seq = seq;
            Effect = effect;
            PayloadId = (byte[])payloadId.Clone();
            Prev = (byte[])prev.Clone();
        }

        /// <summary>The deterministic-CBOR encoding {1: flow_open_id, 2: seq, 3: effect, 4: payload_id, 5: prev}.</summary>
        public byte[] Bytes()
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.B(FlowOpenId)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.U(Seq)),
                new Cbor.Pair(new Cbor.U(3), new Cbor.U(Effect)),
                new Cbor.Pair(new Cbor.U(4), new Cbor.B(PayloadId)),
                new Cbor.Pair(new Cbor.U(5), new Cbor.B(Prev)),
            }));
        }

        /// <summary>This link's SHA-384 head — the prev of the next link.</summary>
        public byte[] Head() => HeadOf(Bytes());

        // ---- helpers -------------------------------------------------------------------------------

        private static byte[] HeadOf(byte[] b) => SHA384.HashData(b);

        /// <summary>Whether <paramref name="v"/> is a value of the closed C5 effect lattice (0..3). An
        /// out-of-lattice value is rejected RangeError, NEVER normalized to destructive — normalizing a
        /// CEILING to destructive would silently make an out-of-range ceiling the MOST-permissive one (a
        /// fail-open).</summary>
        private static bool InLattice(long v) => v >= 0 && v <= Policy.DESTRUCTIVE;

        private static NaalpException WrongFlow() => new NaalpException("WrongFlow", "object's flow_open_id does not match the FlowOpen");

        private static NaalpException Malformed() => new NaalpException("ContMalformed", "object is not a well-formed N-AALP-CONT body");

        private static NaalpException Range() => new NaalpException("RangeError", "effect or effect_ceiling is outside the closed 0..3 lattice");

        // ---- FlowOpen: the one full signature fixing the flow's authority (design §20.2) -----------

        /// <summary>Fixes a flow's identity, effect ceiling, and approval bindings. Signed with one full
        /// ML-DSA signature; its authority is reconstructable from its bytes alone.</summary>
        public sealed class FlowOpen
        {
            public readonly byte[] FlowId;
            public readonly long EffectCeiling;
            public readonly List<byte[]> Approvals;

            public FlowOpen(byte[] flowId, long effectCeiling, List<byte[]> approvals)
            {
                FlowId = (byte[])flowId.Clone();
                EffectCeiling = effectCeiling;
                Approvals = new List<byte[]>(approvals.Count);
                foreach (byte[] a in approvals)
                {
                    Approvals.Add((byte[])a.Clone());
                }
            }

            /// <summary>The deterministic-CBOR encoding {1: flow_id, 2: effect_ceiling, 3: approvals[]}.</summary>
            public byte[] Bytes()
            {
                var arr = new List<Cbor.Value>(Approvals.Count);
                foreach (byte[] a in Approvals)
                {
                    arr.Add(new Cbor.B(a));
                }
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(FlowId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(EffectCeiling)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.A(arr)),
                }));
            }

            /// <summary>The FlowOpen's SHA-384 head — the genesis prev that anchors the continuation chain.</summary>
            public byte[] Head() => HeadOf(Bytes());

            /// <summary>The FlowOpen's content-id — carried by every child object.</summary>
            public byte[] Id() => Cbor.ContentId(Bytes());
        }

        /// <summary>Reconstruct a FlowOpen from its body bytes ALONE (the bearer-authority property). An
        /// out-of-lattice effect_ceiling is rejected RangeError on decode, never normalized. Fail-closed
        /// (ContMalformed) on any malformed shape.</summary>
        public static FlowOpen ParseFlowOpen(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            byte[]? fid = BstrField(m, 1);
            long? ceil = UintField(m, 2);
            Cbor.Value? appsV = Field(m, 3);
            if (fid == null || ceil == null || !(appsV is Cbor.A arr))
            {
                throw Malformed();
            }
            if (!InLattice(ceil.Value))
            {
                throw Range();
            }
            var apps = new List<byte[]>(arr.Items.Count);
            foreach (Cbor.Value e in arr.Items)
            {
                if (!(e is Cbor.B bs))
                {
                    throw Malformed();
                }
                apps.Add(bs.V);
            }
            return new FlowOpen(fid, ceil.Value, apps);
        }

        // ---- Continuation decode / verify (design §20.3) -------------------------------------------

        /// <summary>The single audited decode path for untrusted Continuation wire bytes. Reconstructs
        /// the 5-field body and range-checks the effect against the closed lattice (0..3): an
        /// out-of-lattice effect is rejected RangeError, never carried as an unknown value. Fail-closed
        /// (ContMalformed).</summary>
        public static Continuation ParseContinuation(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            byte[]? fid = BstrField(m, 1);
            long? seq = UintField(m, 2);
            long? effect = UintField(m, 3);
            byte[]? pid = BstrField(m, 4);
            byte[]? prev = BstrField(m, 5);
            if (fid == null || seq == null || effect == null || pid == null || prev == null)
            {
                throw Malformed();
            }
            if (!InLattice(effect.Value))
            {
                throw Range();
            }
            return new Continuation(fid, seq.Value, effect.Value, pid, prev);
        }

        /// <summary>The CHEAP-path check of a single link against the flow's fixed authority: same flow
        /// (WrongFlow), next seq (SeqGap), effect within the ceiling (AboveCeiling), and prev chaining to
        /// the previous head (ChainBroken). Performs no signature verification — that is what makes it
        /// cheap. Both the ceiling and the link effect are closed effects; an out-of-lattice value is
        /// RangeError, never normalized (fail-closed).</summary>
        public static void VerifyContinuation(Continuation c, byte[] flowOpenId, byte[] prevHead, long expectedSeq, long ceiling)
        {
            if (!InLattice(ceiling))
            {
                throw Range();
            }
            if (!InLattice(c.Effect))
            {
                throw Range();
            }
            if (!BytesEqual(c.FlowOpenId, flowOpenId))
            {
                throw WrongFlow();
            }
            if (c.Seq != expectedSeq)
            {
                throw new NaalpException("SeqGap", "continuation seq is not the next expected value");
            }
            if (!Policy.Authorizes(ceiling, c.Effect))
            {
                throw new NaalpException("AboveCeiling", "continuation effect exceeds the FlowOpen effect ceiling");
            }
            if (!BytesEqual(c.Prev, prevHead))
            {
                throw new NaalpException("ChainBroken", "continuation prev does not chain to the previous head");
            }
        }

        /// <summary>Verify a whole ordered continuation sequence starting from the FlowOpen and return
        /// the final chain head. The ceiling comes from the FlowOpen, so the cheap path can never exceed
        /// what the one full signature authorized.</summary>
        public static byte[] VerifyChain(FlowOpen open, IReadOnlyList<Continuation> conts)
        {
            if (!InLattice(open.EffectCeiling))
            {
                throw Range();
            }
            byte[] id = open.Id();
            byte[] prev = open.Head();
            long ceiling = open.EffectCeiling;
            for (int i = 0; i < conts.Count; i++)
            {
                VerifyContinuation(conts[i], id, prev, i, ceiling);
                prev = conts[i].Head();
            }
            return prev;
        }

        // ---- Checkpoint: confirm a prefix, detect a gap (design §20.4) -----------------------------

        /// <summary>Asserts the chain head after a contiguous prefix of continuations (seq 0..ThroughSeq).</summary>
        public sealed class Checkpoint
        {
            public readonly byte[] FlowOpenId;
            public readonly long ThroughSeq; // two's-complement bit pattern carries the full u64 range
            public readonly byte[] Head;

            public Checkpoint(byte[] flowOpenId, long throughSeq, byte[] head)
            {
                FlowOpenId = (byte[])flowOpenId.Clone();
                ThroughSeq = throughSeq;
                Head = (byte[])head.Clone();
            }

            /// <summary>The deterministic-CBOR encoding {1: flow_open_id, 2: through_seq, 3: head}. A
            /// through_seq &gt;= 2^63 has no positive <c>long</c> form; the shared encoder refuses a
            /// negative uint, so such a value is decode-only (see the type remarks).</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(FlowOpenId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.U(ThroughSeq)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.B(Head)),
                }));
            }
        }

        /// <summary>The single audited decode path for untrusted Checkpoint wire bytes: the 3-field body
        /// (field 3 a bstr head). A 2-field FlowCommit look-alike is rejected here (missing field 3).
        /// Fail-closed (ContMalformed).</summary>
        public static Checkpoint ParseCheckpoint(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            byte[]? fid = BstrField(m, 1);
            long? through = UintField(m, 2);
            byte[]? h = BstrField(m, 3);
            if (fid == null || through == null || h == null)
            {
                throw Malformed();
            }
            return new Checkpoint(fid, through.Value, h);
        }

        /// <summary>Confirm the prefix is exactly the contiguous sequence seq 0..ThroughSeq and that its
        /// recomputed head matches the checkpoint. A dropped or reordered link — a missing seq, a broken
        /// prev, or the wrong count — is reported GapDetected.</summary>
        public static void VerifyCheckpoint(Checkpoint cp, FlowOpen open, IReadOnlyList<Continuation> prefix)
        {
            if (!BytesEqual(cp.FlowOpenId, open.Id()))
            {
                throw WrongFlow();
            }
            var gap = new NaalpException("GapDetected", "checkpoint reveals a dropped or reordered continuation");
            // ThroughSeq is a 0-based index, so the prefix length is ThroughSeq+1. At ThroughSeq ==
            // u64::MAX (-1L two's-complement) that addition wraps to 0 and would false-accept an EMPTY
            // prefix as covering the whole counter space — reject it as a gap (no MAX+1 contiguous links).
            if (cp.ThroughSeq == -1L) // 0xFFFFFFFFFFFFFFFF == u64::MAX
            {
                throw gap;
            }
            // A real contiguous prefix cannot be longer than int.MaxValue, so any claimed count that does
            // not equal the delivered count (including any >=2^31 or wrapped-negative claim) is a gap.
            if ((long)prefix.Count != cp.ThroughSeq + 1)
            {
                throw gap; // wrong count: a link is missing or extra
            }
            byte[] h;
            try
            {
                h = VerifyChain(open, prefix);
            }
            catch (NaalpException)
            {
                throw gap; // a seq/prev break inside the prefix is a gap
            }
            if (!BytesEqual(cp.Head, h))
            {
                throw gap;
            }
        }

        // ---- FlowCommit: the second full signature binding the whole sequence (design §20.5) --------

        /// <summary>Binds a completed flow's final chain head under one full ML-DSA signature.</summary>
        public sealed class FlowCommit
        {
            public readonly byte[] FlowOpenId;
            public readonly byte[] FinalHead;

            public FlowCommit(byte[] flowOpenId, byte[] finalHead)
            {
                FlowOpenId = (byte[])flowOpenId.Clone();
                FinalHead = (byte[])finalHead.Clone();
            }

            /// <summary>The deterministic-CBOR encoding {1: flow_open_id, 2: final_head} — the 2-field
            /// shape that distinguishes it from the 3-field Checkpoint.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(FlowOpenId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(FinalHead)),
                }));
            }
        }

        // ---- full-signature helpers (FlowOpen / FlowCommit) — real ML-DSA, isolation ---------------

        /// <summary>The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).</summary>
        private static byte[] ProtectedHeader(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        /// <summary>The tagged COSE_Sign1 over the FlowOpen body (the one full signature that opens the flow).</summary>
        public static byte[] SignFlowOpen(FlowOpen o, int alg, byte[] seed) => Cose.CoseSign1(alg, seed, ProtectedHeader(alg), o.Bytes());

        /// <summary>The tagged COSE_Sign1 over the FlowCommit body.</summary>
        public static byte[] SignFlowCommit(FlowCommit c, int alg, byte[] seed) => Cose.CoseSign1(alg, seed, ProtectedHeader(alg), c.Bytes());

        /// <summary>Verify the FlowOpen's full signature, then reconstruct the authority from the signed
        /// body bytes (fail-closed BadSignature). This is the expensive path measured against the cheap one.</summary>
        public static FlowOpen VerifyFlowOpen(byte[] obj, int alg, byte[] pk)
        {
            byte[][] parts = Cose.ParseSign1Raw(obj);
            byte[] tbs = Cose.ToBeSignedRaw(parts[0], parts[1]);
            if (!Cose.CoseVerify1Raw(alg, pk, tbs, parts[2]))
            {
                throw new NaalpException("BadSignature", "flow-open signature does not verify");
            }
            return ParseFlowOpen(parts[1]);
        }

        /// <summary>Verify the FlowCommit's full signature, that it binds this FlowOpen, and that its
        /// final_head equals the chain recomputed over the delivered continuations (CommitMismatch
        /// otherwise).</summary>
        public static FlowCommit VerifyFlowCommit(byte[] obj, int alg, byte[] pk, FlowOpen open, IReadOnlyList<Continuation> conts)
        {
            byte[][] parts = Cose.ParseSign1Raw(obj);
            byte[] tbs = Cose.ToBeSignedRaw(parts[0], parts[1]);
            if (!Cose.CoseVerify1Raw(alg, pk, tbs, parts[2]))
            {
                throw new NaalpException("BadSignature", "flow-commit signature does not verify");
            }
            Cbor.M m = DecodeMap(parts[1]);
            byte[]? fid = BstrField(m, 1);
            byte[]? fh = BstrField(m, 2);
            if (fid == null || fh == null)
            {
                throw Malformed();
            }
            if (!BytesEqual(fid, open.Id()))
            {
                throw WrongFlow();
            }
            byte[] finalHead = VerifyChain(open, conts);
            if (!BytesEqual(fh, finalHead))
            {
                throw new NaalpException("CommitMismatch", "flow commit final_head does not match the recomputed chain");
            }
            return new FlowCommit(fid, fh);
        }

        // ---- small deterministic-CBOR field accessors ---------------------------------------------

        private static Cbor.M DecodeMap(byte[] b)
        {
            Cbor.Value v = Cbor.Decode(b); // strict decoder: throws NonCanonical on a non-canonical body
            if (!(v is Cbor.M m))
            {
                throw Malformed();
            }
            return m;
        }

        private static Cbor.Value? Field(Cbor.M m, long k)
        {
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U u && u.V == k)
                {
                    return p.Val;
                }
            }
            return null;
        }

        private static byte[]? BstrField(Cbor.M m, long k) => Field(m, k) is Cbor.B b ? b.V : null;

        private static long? UintField(Cbor.M m, long k) => Field(m, k) is Cbor.U u ? u.V : (long?)null;

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
