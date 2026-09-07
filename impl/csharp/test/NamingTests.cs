// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C19 — name bindings and the signed A2A task-state profile for the C# SDK (design.md §22;
    /// R-NAME-1..6 and R-A2A-1..7), ported from impl/go/naming and cross-checked against
    /// impl/python/naalp/naming.py. Graded against the shared independent corpus
    /// <c>vectors/naming/cases.json</c> (NOT produced by this code).
    ///
    /// <para>BYTE surface (⟹ csharp == Go == Rust == Python == oracle): every name-binding
    /// body/head/id, the fork sibling, every task-transition body/head/id, the A2A Agent Card
    /// attestation (a C18 import) content-id, the >2^53 seq round-trip, the minimal encodings, the
    /// strict NonCanonical rejection of descending map keys, and the look-alike cross-parser rejection.
    /// FULL-SIG (real deterministic ML-DSA-65, rnd=0): the name-chain verify/fork-proof, the task-chain
    /// verify with the legal-edge table + card binding, and the TWO cross-language signed pins (seq-0
    /// binding + transition) whose SHA-384 is pinned byte-for-byte against Go and Rust.</para>
    /// </summary>
    public sealed class NamingTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        // Go/Rust cross-language pins: the SHA-384 of the deterministic COSE_Sign1 obtained by signing
        // the seq-0 binding / seq-0 transition with the shared all-0x11 32-byte ML-DSA-65 seed. csharp
        // MUST reproduce these byte-for-byte (identical canonical CBOR + identical deterministic ML-DSA).
        private const string PinnedSignedBindingSha384 =
            "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91";
        private const string PinnedSignedTransitionSha384 =
            "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787";

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "naming", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/naming/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static (byte[] Seed, byte[] Pub, string Id) Key(byte seed)
        {
            byte[] s = new byte[32];
            for (int i = 0; i < 32; i++) s[i] = seed;
            byte[] pk = Cose.MldsaKeygen("ML-DSA-65", s);
            string id = Identity.SignerId(Alg, pk);
            return (s, pk, id);
        }

        private static List<Naming.NameBinding> Bindings(JsonElement v)
        {
            JsonElement name = v.GetProperty("name");
            string nm = name.GetProperty("name_utf8").GetString()!;
            var outp = new List<Naming.NameBinding>();
            foreach (JsonElement b in name.GetProperty("bindings").EnumerateArray())
            {
                outp.Add(new Naming.NameBinding(nm, Hb(b.GetProperty("signer_hex").GetString()!),
                    b.GetProperty("seq").GetInt64(), Hb(b.GetProperty("prev_hex").GetString()!)));
            }
            return outp;
        }

        private static List<Naming.Transition> Transitions(JsonElement v)
        {
            JsonElement a2a = v.GetProperty("a2a");
            byte[] task = Encoding.UTF8.GetBytes(a2a.GetProperty("task_utf8").GetString()!);
            byte[] card = Hb(a2a.GetProperty("card").GetProperty("card_id_hex").GetString()!);
            var outp = new List<Naming.Transition>();
            foreach (JsonElement tr in a2a.GetProperty("transitions").EnumerateArray())
            {
                outp.Add(new Naming.Transition(task, card,
                    tr.GetProperty("from").GetInt64(), tr.GetProperty("to").GetInt64(),
                    tr.GetProperty("seq").GetInt64(), Hb(tr.GetProperty("prev_hex").GetString()!)));
            }
            return outp;
        }

        private static List<Description.Operation> CardOps(JsonElement card)
        {
            var ops = new List<Description.Operation>();
            foreach (JsonElement o in card.GetProperty("operations").EnumerateArray())
            {
                ops.Add(new Description.Operation(o.GetProperty("name").GetString()!,
                    o.GetProperty("effect").GetInt64(), o.GetProperty("requires_approval").GetInt64()));
            }
            return ops;
        }

        private static Description.Import CardImport(JsonElement v)
        {
            JsonElement card = v.GetProperty("a2a").GetProperty("card");
            return new Description.Import(
                Hb(card.GetProperty("importer_hex").GetString()!),
                card.GetProperty("format").GetInt64(),
                Hb(card.GetProperty("foreign_hex").GetString()!),
                CardOps(card));
        }

        private static List<byte[]> SignAll(List<Naming.Transition> transitions, byte[] seed)
        {
            var objs = new List<byte[]>();
            foreach (Naming.Transition tr in transitions) objs.Add(Naming.SignTransition(tr, Alg, seed));
            return objs;
        }

        // ---- byte parity against the non-circular oracle -------------------------------------------

        [Fact]
        public void ByteParityAgainstOracle()
        {
            JsonElement v = Vector();
            JsonElement name = v.GetProperty("name");
            List<Naming.NameBinding> bindings = Bindings(v);
            JsonElement bvArr = name.GetProperty("bindings");
            for (int i = 0; i < bindings.Count; i++)
            {
                JsonElement bv = bvArr[i];
                Assert.Equal(bv.GetProperty("body_hex").GetString(), Hex(bindings[i].Bytes()));
                Assert.Equal(bv.GetProperty("head_hex").GetString(), Hex(bindings[i].Head()));
                Assert.Equal(bv.GetProperty("id_hex").GetString(), Hex(bindings[i].Id()));
            }

            // The fork sibling (b' at seq 1) encodes byte-identically.
            JsonElement bp = name.GetProperty("fork").GetProperty("b_prime");
            var bprime = new Naming.NameBinding(name.GetProperty("name_utf8").GetString()!,
                Hb(bp.GetProperty("signer_hex").GetString()!), bp.GetProperty("seq").GetInt64(),
                Hb(bp.GetProperty("prev_hex").GetString()!));
            Assert.Equal(bp.GetProperty("body_hex").GetString(), Hex(bprime.Bytes()));

            List<Naming.Transition> transitions = Transitions(v);
            JsonElement tvArr = v.GetProperty("a2a").GetProperty("transitions");
            for (int i = 0; i < transitions.Count; i++)
            {
                JsonElement tv = tvArr[i];
                Assert.Equal(tv.GetProperty("body_hex").GetString(), Hex(transitions[i].Bytes()));
                Assert.Equal(tv.GetProperty("head_hex").GetString(), Hex(transitions[i].Head()));
                Assert.Equal(tv.GetProperty("id_hex").GetString(), Hex(transitions[i].Id()));
            }

            // The A2A Agent Card attestation (a C18 import) content-id the profile binds — non-circular.
            Description.Import im = CardImport(v);
            JsonElement card = v.GetProperty("a2a").GetProperty("card");
            Assert.Equal(card.GetProperty("import_body_hex").GetString(), Hex(im.Bytes()));
            Assert.Equal(card.GetProperty("card_id_hex").GetString(), Hex(im.Id()));
        }

        // ---- WalkHistory: the signer succession, current signer, one-name rule --------------------

        [Fact]
        public void WalkHistoryMatchesOracle()
        {
            JsonElement v = Vector();
            List<Naming.NameBinding> bindings = Bindings(v);
            List<Naming.NameEvent> events = Naming.WalkHistory(bindings);

            JsonElement walk = v.GetProperty("name").GetProperty("walk");
            Assert.Equal(walk.GetArrayLength(), events.Count);
            for (int i = 0; i < events.Count; i++)
            {
                Assert.Equal(walk[i].GetProperty("seq").GetInt64(), events[i].Seq);
                Assert.Equal(walk[i].GetProperty("signer_hex").GetString(), Hex(events[i].Signer));
            }
            // The current signer is the last event's signer (the most recent rotation).
            Assert.Equal(Hex(bindings[bindings.Count - 1].Signer), Hex(events[events.Count - 1].Signer));

            // A name change mid-chain breaks the walk (a chain is for one name).
            var bad = new List<Naming.NameBinding>
            {
                bindings[0],
                new Naming.NameBinding("other.name", bindings[1].Signer, bindings[1].Seq, bindings[1].Prev),
            };
            var ex = Assert.Throws<NaalpException>(() => Naming.WalkHistory(bad));
            Assert.Equal("NameChainBroken", ex.Kind);
        }

        // ---- DetectHole: a deleted binding leaves a hole at the oracle position --------------------

        [Fact]
        public void NameHoleDetectedWithPosition()
        {
            JsonElement v = Vector();
            List<Naming.NameBinding> bindings = Bindings(v);

            (int cpos, bool chole) = Naming.DetectHole(bindings);
            Assert.False(chole);

            var present = new List<Naming.NameBinding> { bindings[0], bindings[2] };
            (int pos, bool hole) = Naming.DetectHole(present);
            Assert.True(hole);
            Assert.Equal(v.GetProperty("name").GetProperty("hole").GetProperty("first_hole_position").GetInt32(), pos);
        }

        // ---- DetectFork + the non-repudiable NameForkProof (REAL ML-DSA) --------------------------
        // MUTATION ANCHOR: dropping the benign-duplicate guard in DetectFork makes DetectFork(b1, b1)
        // report a fork, flipping Assert.False(dupFork) below.

        [Fact]
        public void NameForkDetectedWithPosition()
        {
            JsonElement v = Vector();
            JsonElement name = v.GetProperty("name");
            List<Naming.NameBinding> bindings = Bindings(v);
            JsonElement bp = name.GetProperty("fork").GetProperty("b_prime");
            var bprime = new Naming.NameBinding(name.GetProperty("name_utf8").GetString()!,
                Hb(bp.GetProperty("signer_hex").GetString()!), bp.GetProperty("seq").GetInt64(),
                Hb(bp.GetProperty("prev_hex").GetString()!));

            (int pos, bool fork) = Naming.DetectFork(bindings[1], bprime);
            Assert.True(fork);
            Assert.Equal(name.GetProperty("fork").GetProperty("position").GetInt32(), pos);

            // Identical bindings are a benign duplicate, not a fork.
            (_, bool dupFork) = Naming.DetectFork(bindings[1], bindings[1]);
            Assert.False(dupFork);

            // A different seq is a legitimate distinct binding, not a fork.
            (_, bool seqFork) = Naming.DetectFork(bindings[1], bindings[2]);
            Assert.False(seqFork);

            // Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
            (byte[] seed, byte[] pub, string id) = Key(0x11);
            (_, byte[] foreignPub, _) = Key(0x22);
            byte[] signedA = Naming.SignBinding(bindings[1], Alg, seed);
            byte[] signedB = Naming.SignBinding(bprime, Alg, seed);

            var fp = new Naming.NameForkProof(Encoding.UTF8.GetBytes(id), signedA, signedB);
            int gotPos = fp.Verify(Cose.PROFILE_PUBLIC, Alg, pub);
            Assert.Equal(name.GetProperty("fork").GetProperty("position").GetInt32(), gotPos);

            // A foreign key does not verify the accused's signatures.
            var exForeign = Assert.Throws<NaalpException>(() => fp.Verify(Cose.PROFILE_PUBLIC, Alg, foreignPub));
            Assert.Equal("BadSignature", exForeign.Kind);

            // An unnamed accused is not evidence.
            var unnamed = new Naming.NameForkProof(Array.Empty<byte>(), signedA, signedB);
            var exUnnamed = Assert.Throws<NaalpException>(() => unnamed.Verify(Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("NameForkProofInvalid", exUnnamed.Kind);

            // Identical bodies (the same signed object twice) are not equivocation.
            var dup = new Naming.NameForkProof(Encoding.UTF8.GetBytes(id), signedA, signedA);
            var exDup = Assert.Throws<NaalpException>(() => dup.Verify(Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("NameForkProofInvalid", exDup.Kind);
        }

        // ---- signed chain verify: honest verifies; reorder/tamper/foreign each rejected ------------

        [Fact]
        public void NameChainVerifyFailClosed()
        {
            JsonElement v = Vector();
            JsonElement name = v.GetProperty("name");
            (byte[] seed, byte[] pub, _) = Key(0x11);
            (_, byte[] foreignPub, _) = Key(0x22);

            // Build a signed chain via the Registrar (a rotation A -> B -> C).
            var reg = new Naming.Registrar(name.GetProperty("name_utf8").GetString()!, Alg, seed);
            var objs = new List<byte[]>();
            var built = new List<Naming.NameBinding>();
            JsonElement bvArr = name.GetProperty("bindings");
            for (int i = 0; i < bvArr.GetArrayLength(); i++)
            {
                (Naming.NameBinding nb, byte[] obj) = reg.Append(Hb(bvArr[i].GetProperty("signer_hex").GetString()!));
                built.Add(nb);
                objs.Add(obj);
                Assert.Equal(bvArr[i].GetProperty("body_hex").GetString(), Hex(nb.Bytes()));
            }

            List<Naming.NameBinding> verified = Naming.VerifyChain(objs, Cose.PROFILE_PUBLIC, Alg, pub);
            List<Naming.NameEvent> events = Naming.WalkHistory(verified);
            Assert.Equal(built.Count, events.Count);

            // A reordered chain breaks the prev/seq linkage.
            var reordered = new List<byte[]> { objs[0], objs[2], objs[1] };
            var exReorder = Assert.Throws<NaalpException>(() => Naming.VerifyChain(reordered, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("NameChainBroken", exReorder.Kind);

            // A tampered object (flip a payload byte) fails its signature.
            byte[] corrupt = (byte[])objs[1].Clone();
            corrupt[corrupt.Length - 1] ^= 0x01;
            var tampered = new List<byte[]> { objs[0], corrupt, objs[2] };
            var exTamper = Assert.Throws<NaalpException>(() => Naming.VerifyChain(tampered, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("BadSignature", exTamper.Kind);

            // A foreign verifier authenticates none of the accused's bindings.
            var exForeign = Assert.Throws<NaalpException>(() => Naming.VerifyChain(objs, Cose.PROFILE_PUBLIC, Alg, foreignPub));
            Assert.Equal("BadSignature", exForeign.Kind);

            // The single-object verify rejects a foreign key with BadSignature.
            var exOne = Assert.Throws<NaalpException>(() => Naming.VerifyBinding(objs[0], Cose.PROFILE_PUBLIC, Alg, foreignPub));
            Assert.Equal("BadSignature", exOne.Kind);
        }

        // StateName maps each A2A code to its §4.1.3 name; an out-of-range code is "unknown". The
        // expected strings are the A2A vocabulary (an independent authority), NOT read back from Naming;
        // a mutation making StateName return a constant flips these assertions.
        [Fact]
        public void StateNameMatchesA2AVocabulary()
        {
            Assert.Equal("submitted", Naming.StateName(Naming.StateSubmitted));
            Assert.Equal("working", Naming.StateName(Naming.StateWorking));
            Assert.Equal("input-required", Naming.StateName(Naming.StateInputRequired));
            Assert.Equal("auth-required", Naming.StateName(Naming.StateAuthRequired));
            Assert.Equal("completed", Naming.StateName(Naming.StateCompleted));
            Assert.Equal("canceled", Naming.StateName(Naming.StateCanceled));
            Assert.Equal("failed", Naming.StateName(Naming.StateFailed));
            Assert.Equal("rejected", Naming.StateName(Naming.StateRejected));
            Assert.Equal("unknown", Naming.StateName(8));
            Assert.Equal("unknown", Naming.StateName(-1));
        }

        // ---- the A2A transition table graded against the independent oracle edge set ---------------

        [Fact]
        public void TransitionTableMatchesOracle()
        {
            JsonElement v = Vector();
            JsonElement a2a = v.GetProperty("a2a");

            Assert.Equal(a2a.GetProperty("legal_edges").GetArrayLength(), Naming.LegalEdges().Count);
            foreach (JsonElement e in a2a.GetProperty("legal_edges").EnumerateArray())
            {
                long from = e[0].GetInt64(), to = e[1].GetInt64();
                Assert.True(Naming.LegalEdge(from, to));
                Naming.VerifyTransition(from, to); // must not throw
            }
            foreach (JsonElement e in a2a.GetProperty("illegal_edges").EnumerateArray())
            {
                long from = e[0].GetInt64(), to = e[1].GetInt64();
                Assert.False(Naming.LegalEdge(from, to));
                var ex = Assert.Throws<NaalpException>(() => Naming.VerifyTransition(from, to));
                Assert.Equal("IllegalTransition", ex.Kind);
            }

            // Categories match the oracle.
            JsonElement states = a2a.GetProperty("states");
            Assert.Equal(states.GetProperty("start").GetInt64(), Naming.StartState);
            foreach (JsonElement s in states.GetProperty("terminal").EnumerateArray())
            {
                Assert.True(Naming.IsTerminal(s.GetInt64()));
            }
            foreach (JsonElement s in states.GetProperty("interrupted").EnumerateArray())
            {
                Assert.True(Naming.IsInterrupted(s.GetInt64()));
            }
            // A terminal state has no legal out-edge.
            foreach (JsonElement s in states.GetProperty("terminal").EnumerateArray())
            {
                for (long to = 0; to < 8; to++)
                {
                    Assert.False(Naming.LegalEdge(s.GetInt64(), to));
                }
            }
        }

        // ---- the signed task chain: legal lifecycle accepted, every rejection exercised ------------

        [Fact]
        public void TaskChainLegalAndIllegal()
        {
            JsonElement v = Vector();
            JsonElement a2a = v.GetProperty("a2a");
            (byte[] seed, byte[] pub, _) = Key(0x11);
            byte[] card = Hb(a2a.GetProperty("card").GetProperty("card_id_hex").GetString()!);
            byte[] task = Encoding.UTF8.GetBytes(a2a.GetProperty("task_utf8").GetString()!);

            // LEGAL ordered lifecycle: submitted->working->input-required->working->completed.
            List<Naming.Transition> transitions = Transitions(v);
            List<byte[]> objs = SignAll(transitions, seed);
            Naming.VerifyTaskChain(objs, card, Cose.PROFILE_PUBLIC, Alg, pub); // must not throw

            // ILLEGAL edge inside a chain: working -> submitted.
            var t0 = new Naming.Transition(task, card, Naming.StateSubmitted, Naming.StateWorking, 0, Naming.Genesis());
            var illegal = new Naming.Transition(task, card, Naming.StateWorking, Naming.StateSubmitted, 1, t0.Head());
            var exIllegal = Assert.Throws<NaalpException>(() =>
                Naming.VerifyTaskChain(SignAll(new List<Naming.Transition> { t0, illegal }, seed), card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("IllegalTransition", exIllegal.Kind);

            // NON-CONTIGUOUS from: input-required != working (t0.To), though the edge itself is legal.
            var nonContig = new Naming.Transition(task, card, Naming.StateInputRequired, Naming.StateWorking, 1, t0.Head());
            var exContig = Assert.Throws<NaalpException>(() =>
                Naming.VerifyTaskChain(SignAll(new List<Naming.Transition> { t0, nonContig }, seed), card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("IllegalTransition", exContig.Kind);

            // BAD START: the seq-0 transition does not leave the start state.
            var badStart = new Naming.Transition(task, card, Naming.StateWorking, Naming.StateInputRequired, 0, Naming.Genesis());
            var exStart = Assert.Throws<NaalpException>(() =>
                Naming.VerifyTaskChain(SignAll(new List<Naming.Transition> { badStart }, seed), card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("IllegalTransition", exStart.Kind);

            // FOREIGN CARD: a transition binding a different attestation than the profile's bound card.
            byte[] foreignCard = Hb(a2a.GetProperty("foreign_card_id_hex").GetString()!);
            var fc = new Naming.Transition(task, foreignCard, Naming.StateSubmitted, Naming.StateWorking, 0, Naming.Genesis());
            var exCard = Assert.Throws<NaalpException>(() =>
                Naming.VerifyTaskChain(SignAll(new List<Naming.Transition> { fc }, seed), card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("ForeignCard", exCard.Kind);

            // GAP: present [t0, t2] (t1 omitted) — the seq/prev linkage breaks.
            var present = new List<byte[]> { objs[0], objs[2] };
            var exGap = Assert.Throws<NaalpException>(() => Naming.VerifyTaskChain(present, card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("TaskChainBroken", exGap.Kind);

            // BAD SIGNATURE: an otherwise-legal chain with a tampered object at index 0.
            byte[] corrupt = (byte[])objs[0].Clone();
            corrupt[corrupt.Length - 1] ^= 0x01;
            var bad = new List<byte[]> { corrupt, objs[1], objs[2], objs[3] };
            var exSig = Assert.Throws<NaalpException>(() => Naming.VerifyTaskChain(bad, card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("BadSignature", exSig.Kind);
        }

        // ---- DetectTaskGap: a deleted transition leaves a gap at the oracle position ---------------

        [Fact]
        public void TaskGapDetectedWithPosition()
        {
            JsonElement v = Vector();
            List<Naming.Transition> transitions = Transitions(v);
            (int cpos, bool cgap) = Naming.DetectTaskGap(transitions);
            Assert.False(cgap);

            var present = new List<Naming.Transition> { transitions[0], transitions[2] };
            (int pos, bool gap) = Naming.DetectTaskGap(present);
            Assert.True(gap);
            Assert.Equal(v.GetProperty("a2a").GetProperty("gap").GetProperty("first_gap_position").GetInt32(), pos);
        }

        // ---- the C18 -> C19 link: the Agent Card attestation binds the task profile ----------------

        [Fact]
        public void CardAttestationBindsProfile()
        {
            JsonElement v = Vector();
            JsonElement a2a = v.GetProperty("a2a");
            (byte[] seed, byte[] pub, _) = Key(0x11);
            Description.Import im = CardImport(v);

            byte[] card = im.Id();
            Assert.Equal(a2a.GetProperty("card").GetProperty("card_id_hex").GetString(), Hex(card));

            // The card attests the operation effect mapping (the A2A skill -> N-AALP effect).
            Assert.True(im.Operation("submit", out Description.Operation submit));
            Assert.Equal(Policy.IDEMPOTENT_WRITE, submit.EffectClass());
            Assert.True(submit.RequiresApprovalFlag());

            // A chain bound to this card verifies.
            List<Naming.Transition> transitions = Transitions(v);
            Naming.VerifyTaskChain(SignAll(transitions, seed), card, Cose.PROFILE_PUBLIC, Alg, pub);

            // A different importer yields a different bound id; a chain carrying it is refused.
            var other = new Description.Import(Encoding.UTF8.GetBytes("IMPORTER_ID_B"), im.Format, im.Foreign, CardOps(a2a.GetProperty("card")));
            Assert.NotEqual(Hex(card), Hex(other.Id()));
            byte[] task = Encoding.UTF8.GetBytes(a2a.GetProperty("task_utf8").GetString()!);
            var otherChain = new List<Naming.Transition>
            {
                new Naming.Transition(task, other.Id(), Naming.StateSubmitted, Naming.StateWorking, 0, Naming.Genesis()),
            };
            var ex = Assert.Throws<NaalpException>(() =>
                Naming.VerifyTaskChain(SignAll(otherChain, seed), card, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("ForeignCard", ex.Kind);
        }

        // ---- malformed bodies are rejected NameMalformed (fail-closed) -----------------------------

        [Fact]
        public void MalformedRejected()
        {
            // A binding body missing field 4 (prev) is malformed (an empty CBOR array).
            var ex1 = Assert.Throws<NaalpException>(() => Naming.ParseNameBinding(new byte[] { 0x80 }));
            Assert.Equal("NameMalformed", ex1.Kind);
            // A transition body that is not a map is malformed (a bare uint 0).
            var ex2 = Assert.Throws<NaalpException>(() => Naming.ParseTransition(new byte[] { 0x00 }));
            Assert.Equal("NameMalformed", ex2.Kind);
        }

        // ---- the TWO cross-language signed pins (csharp == Go == Rust, full-sig) --------------------

        [Fact]
        public void CrossLangSignedBindingPin()
        {
            JsonElement v = Vector();
            Naming.NameBinding nb = Bindings(v)[0];
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = 0x11;
            byte[] obj = Naming.SignBinding(nb, Alg, seed);
            Assert.Equal(PinnedSignedBindingSha384, Hex(SHA384.HashData(obj)));
        }

        [Fact]
        public void CrossLangSignedTransitionPin()
        {
            JsonElement v = Vector();
            Naming.Transition tr = Transitions(v)[0];
            byte[] seed = new byte[32];
            for (int i = 0; i < 32; i++) seed[i] = 0x11;
            byte[] obj = Naming.SignTransition(tr, Alg, seed);
            Assert.Equal(PinnedSignedTransitionSha384, Hex(SHA384.HashData(obj)));
        }

        // ---- Phase 6 edge case #3: a seq > 2^53 round-trips byte-exact (uint64 all the way) --------

        [Fact]
        public void OversizedSeqRoundTrip()
        {
            JsonElement v = Vector();
            JsonElement nameBig = v.GetProperty("name").GetProperty("big_seq");
            long bseq = long.Parse(nameBig.GetProperty("seq_str").GetString()!);
            Assert.True(bseq > (1L << 53));
            var nb = new Naming.NameBinding(v.GetProperty("name").GetProperty("name_utf8").GetString()!,
                Hb(nameBig.GetProperty("signer_hex").GetString()!), bseq, Hb(nameBig.GetProperty("prev_hex").GetString()!));
            Assert.Equal(nameBig.GetProperty("body_hex").GetString(), Hex(nb.Bytes()));
            Naming.NameBinding gotNb = Naming.ParseNameBinding(nb.Bytes());
            Assert.Equal(bseq, gotNb.Seq);

            JsonElement a2aBig = v.GetProperty("a2a").GetProperty("big_seq");
            long tseq = long.Parse(a2aBig.GetProperty("seq_str").GetString()!);
            byte[] task = Encoding.UTF8.GetBytes(v.GetProperty("a2a").GetProperty("task_utf8").GetString()!);
            byte[] card = Hb(v.GetProperty("a2a").GetProperty("card").GetProperty("card_id_hex").GetString()!);
            var tr = new Naming.Transition(task, card, a2aBig.GetProperty("from").GetInt64(),
                a2aBig.GetProperty("to").GetInt64(), tseq, Hb(a2aBig.GetProperty("prev_hex").GetString()!));
            Assert.Equal(a2aBig.GetProperty("body_hex").GetString(), Hex(tr.Bytes()));
            Naming.Transition gotTr = Naming.ParseTransition(tr.Bytes());
            Assert.Equal(tseq, gotTr.Seq);
        }

        // ---- Phase 6 edge case #4: the smallest valid binding and transition ----------------------

        [Fact]
        public void Minimal()
        {
            JsonElement v = Vector();
            JsonElement nameMin = v.GetProperty("name").GetProperty("minimal");
            var nb = new Naming.NameBinding(nameMin.GetProperty("name_utf8").GetString()!,
                Hb(nameMin.GetProperty("signer_hex").GetString()!), nameMin.GetProperty("seq").GetInt64(),
                Hb(nameMin.GetProperty("prev_hex").GetString()!));
            Assert.Equal(nameMin.GetProperty("body_hex").GetString(), Hex(nb.Bytes()));
            Assert.Equal(nameMin.GetProperty("id_hex").GetString(), Hex(nb.Id()));
            Naming.ParseNameBinding(nb.Bytes());

            JsonElement a2aMin = v.GetProperty("a2a").GetProperty("minimal");
            var tr = new Naming.Transition(Hb(a2aMin.GetProperty("task_hex").GetString()!),
                Hb(a2aMin.GetProperty("card_hex").GetString()!), a2aMin.GetProperty("from").GetInt64(),
                a2aMin.GetProperty("to").GetInt64(), a2aMin.GetProperty("seq").GetInt64(),
                Hb(a2aMin.GetProperty("prev_hex").GetString()!));
            Assert.Equal(a2aMin.GetProperty("body_hex").GetString(), Hex(tr.Bytes()));
            Naming.ParseTransition(tr.Bytes());
        }

        // ---- Phase 6 edge case #1: descending map keys are rejected NonCanonical by the decoder ----

        [Fact]
        public void KeysOutOfOrderRejected()
        {
            JsonElement v = Vector();
            JsonElement koo = v.GetProperty("name").GetProperty("keys_out_of_order");
            string canonWant = koo.GetProperty("canonical_binding_body_hex").GetString()!;

            List<Naming.NameBinding> bindings = Bindings(v);
            Assert.Equal(canonWant, Hex(bindings[0].Bytes()));

            Cbor.Decode(Hb(canonWant)); // canonical body decodes
            var ex = Assert.Throws<NaalpException>(() =>
                Cbor.Decode(Hb(koo.GetProperty("noncanonical_binding_body_hex").GetString()!)));
            Assert.Equal("NonCanonical", ex.Kind);
        }

        // ---- Phase 6 edge case #5: each body is rejected by the OTHER's parser (different shapes) --

        [Fact]
        public void LookAlikeRejectedBySibling()
        {
            JsonElement v = Vector();
            JsonElement la = v.GetProperty("name").GetProperty("look_alike");
            byte[] bindingBody = Hb(la.GetProperty("binding_body_hex").GetString()!);
            byte[] transitionBody = Hb(la.GetProperty("transition_body_hex").GetString()!);

            var ex1 = Assert.Throws<NaalpException>(() => Naming.ParseTransition(bindingBody));
            Assert.Equal("NameMalformed", ex1.Kind);
            var ex2 = Assert.Throws<NaalpException>(() => Naming.ParseNameBinding(transitionBody));
            Assert.Equal("NameMalformed", ex2.Kind);
        }
    }
}
