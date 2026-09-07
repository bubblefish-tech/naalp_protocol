// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Naalp
{
    /// <summary>
    /// C19 — name bindings and the signed A2A task-state profile for the C# SDK (design.md §22;
    /// R-NAME-1..6 and R-A2A-1..7), ported from impl/go/naming and cross-checked against
    /// impl/python/naalp/naming.py.
    ///
    /// <para>C19 is two receipt-CHAINED, signed, OFFLINE-WALKABLE surfaces carried on N-AALP's own
    /// signed object. Both reuse the C7 audit receipt-chain construction (§8.1) unchanged — head =
    /// SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head carried in the body
    /// so editing or omitting a record breaks the next record's linkage — and add NO new envelope,
    /// encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed
    /// N-AALP body (COSE_Sign1, §4) over the T1 content-id framing (§2.3).</para>
    ///
    /// <para>Task 4.1 — name bindings: <see cref="NameBinding"/> {1:name,2:signer,3:seq,4:prev} maps a
    /// name to a signer id and CHAINS onto the prior binding. A rotation is a NEW binding at the next
    /// seq. History is WALKABLE offline (<see cref="WalkHistory"/>); a deleted binding leaves a
    /// detectable HOLE (<see cref="DetectHole"/>); two bindings by ONE authority at the SAME (name, seq)
    /// naming DIFFERENT signers are a FORK (<see cref="DetectFork"/> / <see cref="NameForkProof"/>).</para>
    ///
    /// <para>Task 4.2 — the signed A2A task-state profile: the eight A2A TaskState values (imported
    /// vocabulary; the state set and the terminal/interrupted categories are from the A2A spec §4.1.3,
    /// and the legal-edge table is derived from those category rules). A <see cref="Transition"/>
    /// {1:task,2:card,3:from,4:to,5:seq,6:prev} is one receipt-chained signed state transition;
    /// <see cref="VerifyTaskChain"/> enforces the start state, contiguity, the legal-edge table, the
    /// terminal-cannot-continue rule, prev/seq linkage, the card binding, and every signature.</para>
    ///
    /// <para>Every check is fail-closed (§15). The byte surface is graded against
    /// vectors/naming/cases.json; the signed paths use real deterministic ML-DSA-65 and are pinned
    /// byte-for-byte against Go and Rust (the two cross-language signed pins).</para>
    /// </summary>
    public static class Naming
    {
        /// <summary>The width of a chain head / prev link (SHA-384 = 48 bytes). Genesis is zero.</summary>
        public const int HeadSize = 48;

        private static NaalpException Err(string kind, string msg) => new NaalpException(kind, msg);

        /// <summary>A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis).</summary>
        public static byte[] Genesis() => new byte[HeadSize];

        private static byte[] Head(byte[] b) => SHA384.HashData(b);

        // The T1 framing content id: multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body).
        private static byte[] ContentId(byte[] b)
        {
            byte[] d = Head(b);
            byte[] outp = new byte[2 + d.Length];
            outp[0] = 0x20;
            outp[1] = 0x30;
            Array.Copy(d, 0, outp, 2, d.Length);
            return outp;
        }

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

        // ---- COSE_Sign1 helpers (bare {1: alg} protected header, byte-identical to Go cose.Sign1) --

        private static byte[] BareProtected(int alg)
        {
            return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.N(alg)),
            }));
        }

        private static int AlgFromProtected(byte[] prot)
        {
            Cbor.Value pv;
            try
            {
                pv = Cbor.Decode(prot);
            }
            catch (NaalpException)
            {
                throw Err("NameMalformed", "protected header is malformed");
            }
            if (pv is Cbor.M m)
            {
                foreach (Cbor.Pair p in m.Pairs)
                {
                    if (p.K is Cbor.U ku && ku.V == 1)
                    {
                        if (p.Val is Cbor.N n) return (int)n.V;
                        if (p.Val is Cbor.U u) return (int)u.V;
                    }
                }
            }
            throw Err("NameMalformed", "protected header has no alg");
        }

        // Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the
        // payload: alg registry -> profile floor -> key-alg match -> signature. Fail-closed.
        private static byte[] VerifySign1(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[][] parts;
            try
            {
                parts = Cose.ParseSign1Raw(obj);
            }
            catch (NaalpException)
            {
                throw Err("NameMalformed", "malformed COSE object");
            }
            byte[] prot = parts[0];
            byte[] payload = parts[1];
            byte[] sig = parts[2];

            int halg = AlgFromProtected(prot);
            (int level, bool known) = Cose.AlgLevel(halg);
            if (!known)
            {
                throw Err("UnknownAlg", "unregistered alg " + halg);
            }
            if (level < Cose.ProfileMinLevel(profile))
            {
                throw Err("ProfileDowngrade", "signature level below the profile minimum");
            }
            if (halg != alg)
            {
                throw Err("KeyAlgMismatch", "alg " + halg + " does not match the verifier key alg " + alg);
            }
            byte[] tbs = Cose.ToBeSignedRaw(prot, payload);
            if (!Cose.CoseVerify1Raw(halg, pubkey, tbs, sig))
            {
                throw Err("BadSignature", "signature does not verify");
            }
            return payload;
        }

        // ==== Task 4.1 — name bindings ============================================================

        /// <summary>Maps a name to a signer id at a chain position. It chains onto the prior binding for
        /// the same name: Prev is the prior binding's Head (Genesis for seq 0). A key rotation is a new
        /// binding at the next Seq naming the new Signer; the binding is DATED BY Seq.</summary>
        public sealed class NameBinding
        {
            public readonly string Name;
            public readonly byte[] Signer;
            public readonly long Seq;
            public readonly byte[] Prev;

            public NameBinding(string name, byte[] signer, long seq, byte[] prev)
            {
                Name = name;
                Signer = (byte[])signer.Clone();
                Seq = seq;
                Prev = (byte[])prev.Clone();
            }

            /// <summary>Deterministic-CBOR encoding {1: name, 2: signer, 3: seq, 4: prev}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.T(Name)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Signer)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(Seq)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.B(Prev)),
                }));
            }

            /// <summary>The chain head after this binding: SHA-384 of the binding body (48 octets).</summary>
            public byte[] Head() => Naming.Head(Bytes());

            /// <summary>The binding's T1 content-id (50 octets).</summary>
            public byte[] Id() => ContentId(Bytes());
        }

        /// <summary>Reconstruct a NameBinding from its body bytes alone. A body that is not exactly the
        /// {1: tstr, 2: bstr, 3: uint, 4: bstr} map is NameMalformed (fail-closed).</summary>
        public static NameBinding ParseNameBinding(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            if (!TstrField(m, 1, out string name) || !BstrField(m, 2, out byte[] signer)
                || !UintField(m, 3, out long seq) || !BstrField(m, 4, out byte[] prev))
            {
                throw Err("NameMalformed", "object is not a well-formed N-AALP name-binding body");
            }
            return new NameBinding(name, signer, seq, prev);
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the binding body (deterministic ML-DSA).</summary>
        public static byte[] SignBinding(NameBinding nb, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), nb.Bytes());

        /// <summary>Verify the binding's full signature under the profile, then reconstruct it from the
        /// signed body bytes.</summary>
        public static NameBinding VerifyBinding(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifySign1(obj, profile, alg, pubkey);
            return ParseNameBinding(payload);
        }

        /// <summary>A naming authority that appends monotonic signed bindings for ONE name (mirroring the
        /// C7 audit authority). Each Append records a name -> signer mapping at the next chain position; a
        /// rotation is simply an Append naming the new signer.</summary>
        public sealed class Registrar
        {
            private readonly string _name;
            private readonly int _alg;
            private readonly byte[] _seed;
            private byte[] _head;
            private long _seq;

            public Registrar(string name, int alg, byte[] seed)
            {
                _name = name;
                _alg = alg;
                _seed = (byte[])seed.Clone();
                _head = Genesis();
                _seq = 0;
            }

            /// <summary>Record a binding of the registrar's name to <paramref name="subject"/> at the next
            /// chain position, returning the binding and its tagged COSE_Sign1 object. Seq increases by one
            /// per append (monotonic); the chain head advances to the new binding's Head.</summary>
            public (NameBinding Binding, byte[] Obj) Append(byte[] subject)
            {
                var nb = new NameBinding(_name, subject, _seq, _head);
                byte[] obj = SignBinding(nb, _alg, _seed);
                _head = nb.Head();
                _seq++;
                return (nb, obj);
            }
        }

        /// <summary>One step of a walked name history: the chain position and the signer the name mapped
        /// to at that position, with the chain head after it.</summary>
        public sealed class NameEvent
        {
            public readonly long Seq;
            public readonly byte[] Signer;
            public readonly byte[] Head;

            public NameEvent(long seq, byte[] signer, byte[] head)
            {
                Seq = seq;
                Signer = signer;
                Head = head;
            }
        }

        /// <summary>Verify a name-binding chain's structural continuity OFFLINE (no signatures) and return
        /// the ordered signer succession. It requires every binding to name the SAME name, seq i to equal
        /// its index, and prev to link to the previous binding's Head (genesis zero for seq 0). A gap,
        /// reorder, omitted binding, or a name change is NameChainBroken (fail-closed). The CURRENT signer
        /// is the last event's Signer.</summary>
        public static List<NameEvent> WalkHistory(IReadOnlyList<NameBinding> bindings)
        {
            var events = new List<NameEvent>(bindings.Count);
            byte[] h = Genesis();
            string name = "";
            for (int i = 0; i < bindings.Count; i++)
            {
                NameBinding nb = bindings[i];
                if (i == 0)
                {
                    name = nb.Name;
                }
                else if (nb.Name != name)
                {
                    throw Err("NameChainBroken", "a chain is for exactly one name");
                }
                if (nb.Seq != i || !BytesEqual(nb.Prev, h))
                {
                    throw Err("NameChainBroken", "name-binding prev/seq does not chain to the previous binding");
                }
                h = nb.Head();
                events.Add(new NameEvent(nb.Seq, (byte[])nb.Signer.Clone(), (byte[])h.Clone()));
            }
            return events;
        }

        /// <summary>Verify a name-binding chain offline against the authority's key. Each element is the
        /// tagged COSE_Sign1 object for one binding; VerifyChain verifies every signature under the
        /// profile, then enforces structural continuity — same name, seq i == index, prev links to the
        /// previous Head. A bad signature is BadSignature; a broken link, seq gap, or name change is
        /// NameChainBroken. Fail-closed.</summary>
        public static List<NameBinding> VerifyChain(IReadOnlyList<byte[]> objs, int profile, int alg, byte[] pubkey)
        {
            byte[] h = Genesis();
            string name = "";
            var outp = new List<NameBinding>(objs.Count);
            for (int i = 0; i < objs.Count; i++)
            {
                NameBinding nb = VerifyBinding(objs[i], profile, alg, pubkey); // BadSignature / NameMalformed
                if (i == 0)
                {
                    name = nb.Name;
                }
                else if (nb.Name != name)
                {
                    throw Err("NameChainBroken", "a chain is for exactly one name");
                }
                if (nb.Seq != i || !BytesEqual(nb.Prev, h))
                {
                    throw Err("NameChainBroken", "name-binding prev/seq does not chain to the previous binding");
                }
                h = nb.Head();
                outp.Add(nb);
            }
            return outp;
        }

        /// <summary>Report whether a presented (possibly gappy) binding list breaks contiguity — a
        /// deleted/omitted binding — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th
        /// binding's Seq is not i or its Prev does not link to the previous binding's Head. A contiguous
        /// list returns (0, false).</summary>
        public static (int Position, bool Hole) DetectHole(IReadOnlyList<NameBinding> bindings)
        {
            byte[] h = Genesis();
            for (int i = 0; i < bindings.Count; i++)
            {
                NameBinding nb = bindings[i];
                if (nb.Seq != i || !BytesEqual(nb.Prev, h))
                {
                    return (i, true);
                }
                h = nb.Head();
            }
            return (0, false);
        }

        /// <summary>Compare two bindings for the SAME name and report whether they equivocate — the SAME
        /// name and seq but DIFFERENT bodies — and, if so, the seq POSITION at which they conflict. A
        /// different name or seq is a legitimate distinct binding, not a fork; byte-identical bindings are
        /// a benign duplicate. In both non-fork cases returns (0, false).</summary>
        public static (int Position, bool Fork) DetectFork(NameBinding a, NameBinding b)
        {
            if (a.Name != b.Name || a.Seq != b.Seq)
            {
                return (0, false); // different name or seq — not a conflicting pair
            }
            if (BytesEqual(a.Bytes(), b.Bytes()))
            {
                return (0, false); // byte-identical — a benign duplicate
            }
            return ((int)a.Seq, true); // same (name, seq), different body => a fork at this seq
        }

        /// <summary>Non-repudiable evidence of a name fork: two validly-signed NameBinding objects by ONE
        /// authority at the SAME (name, seq) naming DIFFERENT signers, carried as the accused authority's
        /// OWN two signed objects. Because a single verifier checks BOTH signed objects, the proof is
        /// self-contained.</summary>
        public sealed class NameForkProof
        {
            public readonly byte[] Signer;
            public readonly byte[] SignedA;
            public readonly byte[] SignedB;

            public NameForkProof(byte[] signer, byte[] signedA, byte[] signedB)
            {
                Signer = (byte[])signer.Clone();
                SignedA = (byte[])signedA.Clone();
                SignedB = (byte[])signedB.Clone();
            }

            /// <summary>Check that this is a genuine name fork by the authority whose key is (alg,
            /// pubkey), and return the seq POSITION at which it forks. Accepts iff ALL hold: (1) the
            /// signer id is present; (2) BOTH signed objects verify under the key (proving one authority);
            /// (3) the two bindings share one name and seq; and (4) their bodies differ. An unnamed
            /// accused, a different name/seq, or identical bodies is NameForkProofInvalid; a signature
            /// that does not verify propagates BadSignature.</summary>
            public int Verify(int profile, int alg, byte[] pubkey)
            {
                if (Signer.Length == 0)
                {
                    throw Err("NameForkProofInvalid", "an unnamed accused is not evidence");
                }
                NameBinding a = VerifyBinding(SignedA, profile, alg, pubkey);
                NameBinding b = VerifyBinding(SignedB, profile, alg, pubkey);
                (int pos, bool fork) = DetectFork(a, b);
                if (!fork)
                {
                    throw Err("NameForkProofInvalid", "same name+seq identical bodies, or not the same (name, seq)");
                }
                return pos;
            }
        }

        // ==== Task 4.2 — the signed A2A task-state profile ========================================

        // A2A TaskState codes (imported vocabulary; the SET and categories are from A2A spec §4.1.3).
        public const long StateSubmitted = 0;     // acknowledged, not yet started (the start state)
        public const long StateWorking = 1;       // actively processed
        public const long StateInputRequired = 2; // interrupted, awaiting client input
        public const long StateAuthRequired = 3;  // interrupted, awaiting authentication
        public const long StateCompleted = 4;     // terminal success
        public const long StateCanceled = 5;      // terminal, canceled before completion
        public const long StateFailed = 6;        // terminal, finished with an error
        public const long StateRejected = 7;      // terminal, the agent declined the task

        /// <summary>The A2A lifecycle start state (submitted).</summary>
        public const long StartState = StateSubmitted;

        /// <summary>Whether s is one of the eight defined A2A states.</summary>
        public static bool IsState(long s) => s >= StateSubmitted && s <= StateRejected;

        /// <summary>Whether s is a terminal state (completed/canceled/failed/rejected).</summary>
        public static bool IsTerminal(long s)
            => s == StateCompleted || s == StateCanceled || s == StateFailed || s == StateRejected;

        /// <summary>Whether s is an interrupted state (input-required/auth-required).</summary>
        public static bool IsInterrupted(long s) => s == StateInputRequired || s == StateAuthRequired;

        /// <summary>The A2A state name for diagnostics (A2A §4.1.3); an out-of-range code is "unknown".</summary>
        public static string StateName(long s) => s switch
        {
            StateSubmitted => "submitted",
            StateWorking => "working",
            StateInputRequired => "input-required",
            StateAuthRequired => "auth-required",
            StateCompleted => "completed",
            StateCanceled => "canceled",
            StateFailed => "failed",
            StateRejected => "rejected",
            _ => "unknown",
        };

        // The explicit A2A transition table, derived from the A2A category rules (design §22.3): the
        // authoritative source both LegalEdge and VerifyTaskChain consult. Graded csharp == Go == Rust ==
        // oracle against the independently-listed edge set in vectors/naming/cases.json.
        private static readonly HashSet<(long From, long To)> LegalEdgeSet = BuildLegalEdges();

        private static HashSet<(long, long)> BuildLegalEdges()
        {
            long[] active = { StateSubmitted, StateWorking };
            long[] interrupted = { StateInputRequired, StateAuthRequired };
            long[] terminal = { StateCompleted, StateCanceled, StateFailed, StateRejected };
            var m = new HashSet<(long, long)>();
            m.Add((StateSubmitted, StateWorking)); // begin processing (the only active->active edge)
            foreach (long s in active) // active -> interrupted
            {
                foreach (long t in interrupted) m.Add((s, t));
            }
            foreach (long s in active) // active -> terminal
            {
                foreach (long t in terminal) m.Add((s, t));
            }
            foreach (long s in interrupted) // interrupted -> working (client acted)
            {
                m.Add((s, StateWorking));
            }
            foreach (long s in interrupted) // interrupted -> terminal
            {
                foreach (long t in terminal) m.Add((s, t));
            }
            return m;
        }

        /// <summary>Whether (from -> to) is a legal A2A transition edge per the table. A self-loop, an
        /// edge out of a terminal state, an edge touching an undefined state, and any edge not in the
        /// table are all false.</summary>
        public static bool LegalEdge(long from, long to)
        {
            if (!IsState(from) || !IsState(to))
            {
                return false;
            }
            return LegalEdgeSet.Contains((from, to));
        }

        /// <summary>The legal transition table as a list of (from, to) pairs (for enumeration/count).</summary>
        public static List<(long From, long To)> LegalEdges()
        {
            var outp = new List<(long, long)>(LegalEdgeSet);
            outp.Sort((x, y) => x.Item1 != y.Item1 ? x.Item1.CompareTo(y.Item1) : x.Item2.CompareTo(y.Item2));
            return outp;
        }

        /// <summary>The edge-legality gate: returns normally iff (from -> to) is a legal A2A edge, and
        /// throws IllegalTransition otherwise (an unknown edge, a self-loop, an edge out of a terminal
        /// state, or an edge touching an undefined state). Fail-closed.</summary>
        public static void VerifyTransition(long from, long to)
        {
            if (!LegalEdge(from, to))
            {
                throw Err("IllegalTransition", "A2A task transition is not a legal edge");
            }
        }

        /// <summary>One signed, receipt-CHAINED A2A task state transition (design §22.4). It chains onto
        /// the prior transition of the same task: Prev is the prior transition's Head (Genesis for seq 0).
        /// It is DATED BY Seq. Card is the content-id of the A2A Agent Card attestation (a C18
        /// naalp-description-import) that binds this task profile to an agent/operation.</summary>
        public sealed class Transition
        {
            public readonly byte[] Task;
            public readonly byte[] Card;
            public readonly long From;
            public readonly long To;
            public readonly long Seq;
            public readonly byte[] Prev;

            public Transition(byte[] task, byte[] card, long from, long to, long seq, byte[] prev)
            {
                Task = (byte[])task.Clone();
                Card = (byte[])card.Clone();
                From = from;
                To = to;
                Seq = seq;
                Prev = (byte[])prev.Clone();
            }

            /// <summary>Deterministic-CBOR encoding {1: task, 2: card, 3: from, 4: to, 5: seq, 6: prev}.</summary>
            public byte[] Bytes()
            {
                return Cbor.Encode(new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(Task)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(Card)),
                    new Cbor.Pair(new Cbor.U(3), new Cbor.U(From)),
                    new Cbor.Pair(new Cbor.U(4), new Cbor.U(To)),
                    new Cbor.Pair(new Cbor.U(5), new Cbor.U(Seq)),
                    new Cbor.Pair(new Cbor.U(6), new Cbor.B(Prev)),
                }));
            }

            /// <summary>The chain head after this transition: SHA-384 of the transition body (48 octets).</summary>
            public byte[] Head() => Naming.Head(Bytes());

            /// <summary>The transition's T1 content-id (50 octets).</summary>
            public byte[] Id() => ContentId(Bytes());
        }

        /// <summary>Reconstruct a Transition from its body bytes alone. A body that is not exactly the
        /// {1: bstr, 2: bstr, 3: uint, 4: uint, 5: uint, 6: bstr} map is NameMalformed (fail-closed).</summary>
        public static Transition ParseTransition(byte[] b)
        {
            Cbor.M m = DecodeMap(b);
            if (!BstrField(m, 1, out byte[] task) || !BstrField(m, 2, out byte[] card)
                || !UintField(m, 3, out long from) || !UintField(m, 4, out long to)
                || !UintField(m, 5, out long seq) || !BstrField(m, 6, out byte[] prev))
            {
                throw Err("NameMalformed", "object is not a well-formed N-AALP task-transition body");
            }
            return new Transition(task, card, from, to, seq, prev);
        }

        /// <summary>Produce the tagged COSE_Sign1 object over the transition body (deterministic ML-DSA).</summary>
        public static byte[] SignTransition(Transition t, int alg, byte[] seed)
            => Cose.CoseSign1(alg, seed, BareProtected(alg), t.Bytes());

        /// <summary>Verify a transition's full signature under the profile, reconstruct it, AND check that
        /// its edge is legal. A bad signature is BadSignature; an illegal edge is IllegalTransition.</summary>
        public static Transition VerifyTransitionObject(byte[] obj, int profile, int alg, byte[] pubkey)
        {
            byte[] payload = VerifySign1(obj, profile, alg, pubkey);
            Transition t = ParseTransition(payload);
            VerifyTransition(t.From, t.To);
            return t;
        }

        /// <summary>Walk a task's transition chain offline against the authority's key and the bound card
        /// attestation. Each element is the tagged COSE_Sign1 object for one transition. Enforces, in
        /// order and fail-closed: (1) every SIGNATURE (BadSignature otherwise); (2) prev/seq linkage (each
        /// Prev links to the prior Head, seq i == index) — a gap/reorder is TaskChainBroken; (3) the CARD
        /// BINDING (every Card equals <paramref name="card"/>) — ForeignCard otherwise; and (4) the START
        /// STATE (seq-0 From is StartState), CONTIGUITY (each From == the prior To), and the LEGAL-EDGE
        /// TABLE at every step (incl. the terminal-cannot-continue rule) — IllegalTransition otherwise.
        /// Returns the verified, ordered transitions.</summary>
        public static List<Transition> VerifyTaskChain(IReadOnlyList<byte[]> objs, byte[] card, int profile, int alg, byte[] pubkey)
        {
            byte[] h = Genesis();
            long prevTo = 0;
            var outp = new List<Transition>(objs.Count);
            for (int i = 0; i < objs.Count; i++)
            {
                byte[] payload = VerifySign1(objs[i], profile, alg, pubkey); // BadSignature (foreign/tampered)
                Transition t = ParseTransition(payload);
                if (t.Seq != i || !BytesEqual(t.Prev, h))
                {
                    throw Err("TaskChainBroken", "task-transition prev/seq does not chain to the previous transition");
                }
                if (!BytesEqual(t.Card, card))
                {
                    throw Err("ForeignCard", "task transition binds a card other than the profile's bound A2A Agent Card");
                }
                if (i == 0)
                {
                    if (t.From != StartState)
                    {
                        throw Err("IllegalTransition", "the first transition MUST leave the start state");
                    }
                }
                else if (t.From != prevTo)
                {
                    throw Err("IllegalTransition", "non-contiguous: this From must equal the prior To");
                }
                VerifyTransition(t.From, t.To); // an illegal edge (incl. a from-terminal edge)
                h = t.Head();
                prevTo = t.To;
                outp.Add(t);
            }
            return outp;
        }

        /// <summary>Report whether a presented (possibly gappy) transition list breaks contiguity — a
        /// deleted/omitted or reordered transition — and, if so, the FIRST-BROKEN POSITION. A contiguous
        /// list returns (0, false). (The gap-evident detector for the task chain, mirroring
        /// <see cref="DetectHole"/> for name bindings.)</summary>
        public static (int Position, bool Gap) DetectTaskGap(IReadOnlyList<Transition> transitions)
        {
            byte[] h = Genesis();
            for (int i = 0; i < transitions.Count; i++)
            {
                Transition t = transitions[i];
                if (t.Seq != i || !BytesEqual(t.Prev, h))
                {
                    return (i, true);
                }
                h = t.Head();
            }
            return (0, false);
        }

        // ---- small deterministic-CBOR field accessors ---------------------------------------------

        private static Cbor.M DecodeMap(byte[] b)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(b);
            }
            catch (NaalpException)
            {
                throw Err("NameMalformed", "body is not well-formed deterministic CBOR");
            }
            if (!(v is Cbor.M m))
            {
                throw Err("NameMalformed", "body is not a map");
            }
            return m;
        }

        private static bool Field(Cbor.M m, long k, out Cbor.Value v)
        {
            foreach (Cbor.Pair p in m.Pairs)
            {
                if (p.K is Cbor.U ku && ku.V == k)
                {
                    v = p.Val;
                    return true;
                }
            }
            v = null!;
            return false;
        }

        private static bool BstrField(Cbor.M m, long k, out byte[] v)
        {
            if (Field(m, k, out Cbor.Value fv) && fv is Cbor.B b)
            {
                v = b.V;
                return true;
            }
            v = null!;
            return false;
        }

        private static bool TstrField(Cbor.M m, long k, out string v)
        {
            if (Field(m, k, out Cbor.Value fv) && fv is Cbor.T t)
            {
                v = t.V;
                return true;
            }
            v = null!;
            return false;
        }

        private static bool UintField(Cbor.M m, long k, out long v)
        {
            if (Field(m, k, out Cbor.Value fv) && fv is Cbor.U u)
            {
                v = u.V;
                return true;
            }
            v = 0;
            return false;
        }
    }
}
