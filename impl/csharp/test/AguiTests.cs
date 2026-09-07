// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C21 NAALP-AGUI UI-consent-binding conformance for the C# SDK (design.md §24; R-AGUI-1..6),
    /// graded against the shared independent corpus <c>vectors/agui/cases.json</c> (NOT produced by this
    /// code): the receipt-chained shown-event bodies/heads/ids, the running and final chain heads, the
    /// genesis prev, the >2^53 seq carried byte-exact (big_seq), the minimal and empty-vs-absent bodies,
    /// the non-canonical / malformed rejections, and the omitted-shown-event HOLE detected at its
    /// POSITION.
    ///
    /// <para>The signed shown-chain and the UI consent binding — which REUSES the just-landed C#
    /// <see cref="Approval"/> §7 approval UNCHANGED — use REAL deterministic ML-DSA-65 (BouncyCastle,
    /// rnd=0) and are demonstrated in isolation on the corpus action bytes (the corpus carries no signed
    /// vector; F2/F4, honest): a valid consent binds the shown-and-approved action; a SUBSTITUTED action
    /// (different content id) is rejected ActionSubstituted; a chain with no approved event is
    /// UINoConsent. Ported from impl/go/agui; mirrors impl/python/naalp/agui.py.</para>
    /// </summary>
    public sealed class AguiTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "agui", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/agui/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);

        private static Agui.UIEvent EventOf(JsonElement ev, byte[] session)
        {
            return new Agui.UIEvent(
                session,
                ev.GetProperty("kind").GetInt64(),
                Hb(ev.GetProperty("action_hex").GetString()!),
                ev.GetProperty("seq").GetInt64(),
                Hb(ev.GetProperty("prev_hex").GetString()!));
        }

        // ---- the receipt-chained shown-event bodies, running heads, and final head -----------------
        // Also grades the closed genesis (48 zero bytes) and each event's content id.

        [Fact]
        public void ChainBodiesAndHeadsMatchOracle()
        {
            JsonElement v = Vector();
            byte[] session = Hb(v.GetProperty("session_hex").GetString()!);
            Assert.Equal(v.GetProperty("genesis_hex").GetString(), Hex(Agui.Genesis()));

            JsonElement chain = v.GetProperty("chain");
            byte[] running = Agui.Genesis();
            int count = 0;
            foreach (JsonElement ev in chain.GetProperty("events").EnumerateArray())
            {
                Agui.UIEvent e = EventOf(ev, session);
                Assert.Equal(ev.GetProperty("prev_hex").GetString(), Hex(running)); // prev links to the running head
                Assert.Equal(ev.GetProperty("body_hex").GetString(), Hex(e.Bytes()));
                Assert.Equal(ev.GetProperty("head_hex").GetString(), Hex(e.Head()));
                Assert.Equal(ev.GetProperty("id_hex").GetString(), Hex(e.Id()));
                running = e.Head();
                count++;
            }
            Assert.Equal(chain.GetProperty("final_head_hex").GetString(), Hex(running));
            Assert.True(count > 0, "corpus carried no chain events");
        }

        // ---- a >2^53 seq round-trips byte-exact (carried as a decimal string, not a JSON number) ---

        [Fact]
        public void BigSeqByteExact()
        {
            JsonElement v = Vector();
            byte[] session = Hb(v.GetProperty("session_hex").GetString()!);
            JsonElement bs = v.GetProperty("big_seq");
            long seq = long.Parse(bs.GetProperty("seq_str").GetString()!); // 72623859790382856 > 2^53
            Assert.True(seq > (1L << 53));
            var e = new Agui.UIEvent(session, bs.GetProperty("kind").GetInt64(), Hb(bs.GetProperty("action_hex").GetString()!),
                seq, Hb(bs.GetProperty("prev_hex").GetString()!));
            Assert.Equal(bs.GetProperty("body_hex").GetString(), Hex(e.Bytes()));
            Assert.Equal(bs.GetProperty("head_hex").GetString(), Hex(e.Head()));
            Assert.Equal(bs.GetProperty("id_hex").GetString(), Hex(e.Id()));
        }

        // ---- minimal, empty-vs-absent, non-canonical, and look-alike edge cases --------------------

        [Fact]
        public void EdgeCasesMatchOracle()
        {
            JsonElement v = Vector();

            JsonElement min = v.GetProperty("minimal");
            var minE = new Agui.UIEvent(Hb(min.GetProperty("session_hex").GetString()!), min.GetProperty("kind").GetInt64(),
                Hb(min.GetProperty("action_hex").GetString()!), min.GetProperty("seq").GetInt64(), Hb(min.GetProperty("prev_hex").GetString()!));
            Assert.Equal(min.GetProperty("body_hex").GetString(), Hex(minE.Bytes()));
            Assert.Equal(min.GetProperty("head_hex").GetString(), Hex(minE.Head()));
            Assert.Equal(min.GetProperty("id_hex").GetString(), Hex(minE.Id()));

            JsonElement eva = v.GetProperty("edge_cases").GetProperty("empty_vs_absent");
            byte[] session = Hb(v.GetProperty("session_hex").GetString()!);

            // an empty action bstr is PRESENT and valid, distinct by content id from a populated one.
            var emptyAction = new Agui.UIEvent(session, 0, Array.Empty<byte>(), 0, Agui.Genesis());
            Assert.Equal(eva.GetProperty("empty_action").GetProperty("id_hex").GetString(), Hex(emptyAction.Id()));
            var populated = new Agui.UIEvent(session, 0, Hb(eva.GetProperty("populated_action").GetProperty("action_hex").GetString()!), 0, Agui.Genesis());
            Assert.Equal(eva.GetProperty("populated_action").GetProperty("id_hex").GetString(), Hex(populated.Id()));
            Assert.NotEqual(Hex(emptyAction.Id()), Hex(populated.Id()));

            // a body whose mandatory field 3 (action) is ABSENT is rejected UIMalformed.
            var abEx = Assert.Throws<NaalpException>(() => Agui.ParseUIEvent(Hb(eva.GetProperty("absent_field").GetProperty("body_hex").GetString()!)));
            Assert.Equal(eva.GetProperty("absent_field").GetProperty("reject").GetString(), abEx.Kind);

            // a ui-event-shaped body lacking its field-5 back-pointer (prev) is rejected UIMalformed.
            JsonElement la = v.GetProperty("edge_cases").GetProperty("look_alike");
            var laEx = Assert.Throws<NaalpException>(() => Agui.ParseUIEvent(Hb(la.GetProperty("body_hex").GetString()!)));
            Assert.Equal(la.GetProperty("reject").GetString(), laEx.Kind);

            // keys emitted descending -> the strict decoder rejects (surfaced as UIMalformed by the parser).
            JsonElement koo = v.GetProperty("edge_cases").GetProperty("keys_out_of_order");
            var ncEx = Assert.Throws<NaalpException>(() => Agui.ParseUIEvent(Hb(koo.GetProperty("noncanonical_body_hex").GetString()!)));
            Assert.Equal("UIMalformed", ncEx.Kind);
            // the canonical form parses cleanly.
            Agui.ParseUIEvent(Hb(koo.GetProperty("canonical_body_hex").GetString()!));
        }

        // ---- an unknown kind is rejected; a walked chain enforces contiguity -----------------------

        [Fact]
        public void KindVocabularyAndWalk()
        {
            JsonElement v = Vector();
            byte[] session = Hb(v.GetProperty("session_hex").GetString()!);
            foreach (JsonElement k in v.GetProperty("kind_vocabulary").EnumerateArray())
            {
                Assert.True(Agui.IsKnownKind(k.GetProperty("code").GetInt64()));
            }
            Assert.False(Agui.IsKnownKind(v.GetProperty("unknown_kind").GetInt64())); // 99

            // walking the honest 3-event chain succeeds and preserves the shown action ids.
            var full = new List<Agui.UIEvent>();
            foreach (JsonElement ev in v.GetProperty("chain").GetProperty("events").EnumerateArray())
            {
                full.Add(EventOf(ev, session));
            }
            List<Agui.ShownEvent> shown = Agui.WalkShown(full);
            Assert.Equal(full.Count, shown.Count);
            Assert.Equal(v.GetProperty("chain").GetProperty("final_head_hex").GetString(), Hex(shown[shown.Count - 1].Head));
        }

        // ---- an omitted shown-event is a detectable HOLE at its POSITION ---------------------------
        // MUTATION ANCHOR: DetectHole returning (0,false) fails Assert.True(hole) — the gap-evidence
        // property (a removed shown-event leaves a hole where it should have been).

        [Fact]
        public void HoleDetectedAtPosition()
        {
            JsonElement v = Vector();
            byte[] session = Hb(v.GetProperty("session_hex").GetString()!);
            JsonElement events = v.GetProperty("chain").GetProperty("events");

            // the gappy chain: present ev0 and ev2, the middle shown-event (ev1) omitted.
            var gappy = new List<Agui.UIEvent> { EventOf(events[0], session), EventOf(events[2], session) };

            (int pos, bool hole) = Agui.DetectHole(gappy);
            Assert.True(hole);
            Assert.Equal(v.GetProperty("hole").GetProperty("position").GetInt32(), pos);

            // the contiguous full chain has no hole.
            var full = new List<Agui.UIEvent> { EventOf(events[0], session), EventOf(events[1], session), EventOf(events[2], session) };
            (_, bool fullHole) = Agui.DetectHole(full);
            Assert.False(fullHole);

            // WalkShown rejects the gappy chain (fail-closed) — the same broken link.
            var wex = Assert.Throws<NaalpException>(() => Agui.WalkShown(gappy));
            Assert.Equal("UIChainBroken", wex.Kind);
        }

        // ---- the signed shown-chain + the UI consent binding (REAL ML-DSA, isolation) --------------

        [Fact]
        public void ConsentBindsExactShownAction()
        {
            JsonElement v = Vector();
            byte[] session = Hb(v.GetProperty("session_hex").GetString()!);
            byte[] actionCid = Hb(v.GetProperty("action_cid_hex").GetString()!);
            byte[] actionBytes = Hb(v.GetProperty("action_bytes_hex").GetString()!);
            byte[] substituted = Hb(v.GetProperty("substituted_bytes_hex").GetString()!);

            // non-circular: the action content ids come from the corpus, recomputed here from the bytes.
            Assert.Equal(v.GetProperty("action_cid_hex").GetString(), Hex(Agui.ContentId(actionBytes)));
            Assert.Equal(v.GetProperty("substituted_cid_hex").GetString(), Hex(Agui.ContentId(substituted)));

            // the UI authority signs the shown chain (shown, args-shown, approved).
            byte[] uiSeed = new byte[32];
            for (int i = 0; i < 32; i++) uiSeed[i] = 41;
            byte[] uiPk = Cose.MldsaKeygen("ML-DSA-65", uiSeed);
            var objs = new List<byte[]>();
            var chain = new List<Agui.UIEvent>();
            foreach (JsonElement ev in v.GetProperty("chain").GetProperty("events").EnumerateArray())
            {
                Agui.UIEvent e = EventOf(ev, session);
                chain.Add(e);
                objs.Add(Agui.SignUIEvent(e, Alg, uiSeed));
            }
            List<Agui.UIEvent> verified = Agui.VerifyShownChain(objs, Cose.PROFILE_PUBLIC, Alg, uiPk);
            Assert.Equal(chain.Count, verified.Count);

            // the human approval binds the shown-and-approved action content id.
            byte[] humanSeed = new byte[32];
            for (int i = 0; i < 32; i++) humanSeed[i] = 43;
            byte[] humanPk = Cose.MldsaKeygen("ML-DSA-65", humanSeed);
            var appr = new Approval.ApprovalRecord(actionCid, "human", Policy.NON_IDEMPOTENT_WRITE, new byte[] { 5, 5 }, 1000);
            byte[] apprSig = Approval.SignApproval(appr, Alg, humanSeed);

            // honest consent: the executed action IS the shown-and-approved one -> authorized.
            Agui.VerifyConsent(chain, actionBytes, appr, Alg, humanPk, apprSig, 500);

            // a SUBSTITUTED action (different content id) is rejected.
            var subEx = Assert.Throws<NaalpException>(() => Agui.VerifyConsent(chain, substituted, appr, Alg, humanPk, apprSig, 500));
            Assert.Equal("ActionSubstituted", subEx.Kind);

            // a chain with no approved event has no consent to bind.
            var shownOnly = new List<Agui.UIEvent> { chain[0] };
            var ncEx = Assert.Throws<NaalpException>(() => Agui.VerifyConsent(shownOnly, actionBytes, appr, Alg, humanPk, apprSig, 500));
            Assert.Equal("UINoConsent", ncEx.Kind);

            // an expired approval is rejected (the §7 approval expiry, reused unchanged).
            var expEx = Assert.Throws<NaalpException>(() => Agui.VerifyConsent(chain, actionBytes, appr, Alg, humanPk, apprSig, 1001));
            Assert.Equal("ApprovalExpired", expEx.Kind);

            // an approval verified under the WRONG key is BadSignature (fail-closed).
            byte[] foreignSeed = new byte[32];
            for (int i = 0; i < 32; i++) foreignSeed[i] = 88;
            byte[] foreignPk = Cose.MldsaKeygen("ML-DSA-65", foreignSeed);
            var bsEx = Assert.Throws<NaalpException>(() => Agui.VerifyConsent(chain, actionBytes, appr, Alg, foreignPk, apprSig, 500));
            Assert.Equal("BadSignature", bsEx.Kind);
        }
    }
}
