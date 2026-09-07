// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// C20 — governed negotiation, advisory risk labels, and trust references for the C# SDK
    /// (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4), ported from impl/go/negotiation and
    /// cross-checked against impl/python/naalp/negotiation.py. Graded against the shared independent
    /// corpus <c>vectors/negotiation/cases.json</c> (NOT produced by this code).
    ///
    /// <para>BYTE surface (⟹ csharp == Go == Rust == Python == oracle): every message body/head/id
    /// (offer/counter/accept + the negatives), every labeled-object body/head/id (with and without
    /// labels), every risk-label sample body, both trust-ref bodies/heads/ids, the wire edge cases
    /// (descending keys → NonCanonical, empty-vs-absent, minimal, look-alike). FULL-SIG (real
    /// deterministic ML-DSA-65, rnd=0): the message/labeled/trust-ref sign+verify round-trips, the
    /// closed-set rejections, and the THREE cross-language signed pins (offer / labeled-object /
    /// trust-ref) whose SHA-384 is pinned byte-for-byte against Go and Rust.</para>
    /// </summary>
    public sealed class NegotiationTests
    {
        private const int Alg = Cose.ALG_MLDSA65;

        // Go/Rust cross-language pins: the SHA-384 of the deterministic COSE_Sign1 obtained by signing
        // the offer body / the read_only-with-labels labeled-object body / the trust-ref A body with the
        // shared all-0x11 32-byte ML-DSA-65 seed (impl/go/negotiation/negotiation_test.go). csharp MUST
        // reproduce these byte-for-byte (identical canonical CBOR + identical deterministic ML-DSA).
        private const string PinnedSignedOfferSha384 =
            "28b5c4e082cfae270bcc0317ef95c88c451f5af7c0d984b2120496afad4870964845b699fe501bb8cd6fab99298729fd";
        private const string PinnedSignedLabeledSha384 =
            "c6f4ba4c897f2f34f075ec504cd8329da7b138764cac5f4b7dcd120348b15d36fab9bf55bb5302dd024f1b077ecc1a0c";
        private const string PinnedSignedTrustRefSha384 =
            "80a7d8302bdb01d0fec577a28a4cb0e37c540f80c4d588a8be8324d9e80229fbf3f6a850c6c50d24ca1991e03b84699f";

        private static JsonElement Vector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 12 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "negotiation", "cases.json");
                if (File.Exists(p))
                {
                    return JsonDocument.Parse(File.ReadAllText(p)).RootElement.Clone();
                }
                d = d.Parent;
            }
            throw new Xunit.Sdk.XunitException("vectors/negotiation/cases.json not found from " + AppContext.BaseDirectory);
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
        private static byte[] Hb(string s) => Convert.FromHexString(s);
        private static byte[] Sha384(byte[] b) { using var h = SHA384.Create(); return h.ComputeHash(b); }

        private static (byte[] Seed, byte[] Pub) Key(byte seed)
        {
            byte[] s = new byte[32];
            for (int i = 0; i < 32; i++) s[i] = seed;
            return (s, Cose.MldsaKeygen("ML-DSA-65", s));
        }

        private static List<byte[]> Causes(JsonElement mv)
        {
            var outp = new List<byte[]>();
            foreach (JsonElement c in mv.GetProperty("causes_hex").EnumerateArray())
            {
                outp.Add(Hb(c.GetString()!));
            }
            return outp;
        }

        private static Negotiation.Message MsgFrom(byte[] neg, JsonElement mv)
        {
            return new Negotiation.Message(neg, mv.GetProperty("role").GetInt64(),
                mv.GetProperty("profile").GetInt64(), Causes(mv));
        }

        private static List<Negotiation.RiskLabel> CarriedLabels(JsonElement v)
        {
            var outp = new List<Negotiation.RiskLabel>();
            foreach (JsonElement c in v.GetProperty("risk").GetProperty("carried_on_labeled_objects").EnumerateArray())
            {
                outp.Add(new Negotiation.RiskLabel(c.GetProperty("code").GetInt64(), c.GetProperty("critical").GetInt64()));
            }
            return outp;
        }

        // ---- byte parity: every negotiation message body/head/id against the oracle ----------------

        [Fact]
        public void MessageByteParityAgainstOracle()
        {
            JsonElement v = Vector();
            JsonElement neg = v.GetProperty("negotiation");
            byte[] negId = Hb(neg.GetProperty("negotiation_hex").GetString()!);
            foreach (string name in new[]
                { "offer", "counter", "accept", "offer2", "accept_not_descended", "unknown_profile_offer", "unknown_role_message" })
            {
                JsonElement mv = neg.GetProperty(name);
                Negotiation.Message m = MsgFrom(negId, mv);
                Assert.Equal(mv.GetProperty("body_hex").GetString(), Hex(m.Bytes()));
                Assert.Equal(mv.GetProperty("head_hex").GetString(), Hex(m.Head()));
                Assert.Equal(mv.GetProperty("id_hex").GetString(), Hex(m.Id()));
            }
        }

        // ---- labeled-object byte parity AND the load-bearing effect-class-unchanged invariant -------

        [Fact]
        public void LabeledObjectByteParityAndEffectInvariant()
        {
            JsonElement v = Vector();
            List<Negotiation.RiskLabel> carried = CarriedLabels(v);
            foreach (JsonElement lo in v.GetProperty("risk").GetProperty("labeled_objects").EnumerateArray())
            {
                long effect = lo.GetProperty("effect").GetInt64();
                long effectClass = lo.GetProperty("effect_class").GetInt64();

                var with = new Negotiation.LabeledObject(effect, carried);
                var without = new Negotiation.LabeledObject(effect, new List<Negotiation.RiskLabel>());

                JsonElement wl = lo.GetProperty("with_labels");
                Assert.Equal(wl.GetProperty("body_hex").GetString(), Hex(with.Bytes()));
                Assert.Equal(wl.GetProperty("head_hex").GetString(), Hex(with.Head()));
                Assert.Equal(wl.GetProperty("id_hex").GetString(), Hex(with.Id()));

                JsonElement nl = lo.GetProperty("without_labels");
                Assert.Equal(nl.GetProperty("body_hex").GetString(), Hex(without.Bytes()));
                Assert.Equal(nl.GetProperty("head_hex").GetString(), Hex(without.Head()));
                Assert.Equal(nl.GetProperty("id_hex").GetString(), Hex(without.Id()));

                // The load-bearing C20 invariant: carrying a risk label NEVER changes the effect class.
                Assert.Equal(effectClass, with.EffectClass());
                Assert.Equal(without.EffectClass(), with.EffectClass());
            }
        }

        // ---- risk-label sample bodies + the R-2.5 critical-extension rule ---------------------------

        [Fact]
        public void RiskLabelSamplesAndValidate()
        {
            JsonElement v = Vector();
            JsonElement samples = v.GetProperty("risk").GetProperty("sample_labels");
            foreach (JsonProperty sp in samples.EnumerateObject())
            {
                var l = new Negotiation.RiskLabel(sp.Value.GetProperty("code").GetInt64(),
                    sp.Value.GetProperty("critical").GetInt64());
                Assert.Equal(sp.Value.GetProperty("body_hex").GetString(), Hex(l.Bytes()));
            }

            JsonElement rs = v.GetProperty("risk").GetProperty("validate").GetProperty("recognized_set");
            var carried = new List<Negotiation.RiskLabel>();
            foreach (JsonElement c in rs.GetProperty("carried").EnumerateArray())
            {
                carried.Add(new Negotiation.RiskLabel(c.GetProperty("code").GetInt64(), c.GetProperty("critical").GetInt64()));
            }
            List<Negotiation.RiskLabel> recognized = Negotiation.ValidateLabels(carried);
            var wantCodes = new List<long>();
            foreach (JsonElement rc in rs.GetProperty("recognized_codes").EnumerateArray()) wantCodes.Add(rc.GetInt64());
            Assert.Equal(wantCodes.Count, recognized.Count);
            for (int i = 0; i < recognized.Count; i++) Assert.Equal(wantCodes[i], recognized[i].Code);

            // An unknown CRITICAL label is rejected (R-2.5).
            JsonElement ucr = v.GetProperty("risk").GetProperty("validate").GetProperty("unknown_critical_rejected");
            var badCarried = new List<Negotiation.RiskLabel>();
            foreach (JsonElement c in ucr.GetProperty("carried").EnumerateArray())
            {
                badCarried.Add(new Negotiation.RiskLabel(c.GetProperty("code").GetInt64(), c.GetProperty("critical").GetInt64()));
            }
            var ex = Assert.Throws<NaalpException>(() => Negotiation.ValidateLabels(badCarried));
            Assert.Equal(ucr.GetProperty("error").GetString(), ex.Kind);
        }

        // ---- the C20 descent DAG governs which accept is admissible (MUTATION ANCHOR) --------------
        // MUTATION ANCHOR: forcing the private causal-reachability walk (`descends`) to a constant true
        // makes the non-descended accept report descent, flipping Assert.False(...) and the
        // Assert.Throws(NotDescended) below.

        [Fact]
        public void DescentDagGovernsAccept()
        {
            JsonElement v = Vector();
            JsonElement neg = v.GetProperty("negotiation");
            byte[] negId = Hb(neg.GetProperty("negotiation_hex").GetString()!);

            Negotiation.Message offer = MsgFrom(negId, neg.GetProperty("offer"));
            Negotiation.Message counter = MsgFrom(negId, neg.GetProperty("counter"));
            Negotiation.Message accept = MsgFrom(negId, neg.GetProperty("accept"));
            Negotiation.Message offer2 = MsgFrom(negId, neg.GetProperty("offer2"));
            Negotiation.Message acceptBad = MsgFrom(negId, neg.GetProperty("accept_not_descended"));

            var byId = Negotiation.IndexById(new List<Negotiation.Message> { offer, counter, accept, offer2, acceptBad });

            // The accept descends from the offer along the causes chain (through the counter).
            Assert.True(Negotiation.Descends(accept, offer, byId));
            Assert.Equal(neg.GetProperty("descends").GetProperty("accept_from_offer").GetBoolean(),
                Negotiation.Descends(accept, offer, byId));

            // The non-descended accept does NOT descend from THIS offer (it descends from offer2).
            Assert.False(Negotiation.Descends(acceptBad, offer, byId));
            Assert.Equal(neg.GetProperty("descends").GetProperty("accept_bad_from_offer").GetBoolean(),
                Negotiation.Descends(acceptBad, offer, byId));

            // VerifyAccept returns the agreed pre-registered profile for the genuine descent.
            long agreed = Negotiation.VerifyAccept(accept, offer, byId);
            Assert.Equal(neg.GetProperty("agreed_profile").GetInt64(), agreed);

            // VerifyAccept REJECTS the non-descended accept (fail-closed NotDescended).
            var ex = Assert.Throws<NaalpException>(() => Negotiation.VerifyAccept(acceptBad, offer, byId));
            Assert.Equal("NotDescended", ex.Kind);
        }

        // ---- trust-ref recompute + symmetry + tamper ------------------------------------------------

        [Fact]
        public void TrustRefRecomputeAndTamper()
        {
            JsonElement v = Vector();
            JsonElement t = v.GetProperty("trust");
            byte[] regA = Hb(t.GetProperty("registry_a_hex").GetString()!);
            byte[] regB = Hb(t.GetProperty("registry_b_hex").GetString()!);
            byte[] subject = Hb(t.GetProperty("subject_hex").GetString()!);
            byte[] reference = Hb(t.GetProperty("reference_hex").GetString()!);
            byte[] record = Hb(t.GetProperty("external_record_hex").GetString()!);
            byte[] tamperedRecord = Hb(t.GetProperty("tampered_record_hex").GetString()!);

            var refA = new Negotiation.TrustRef(regA, reference, subject);
            var refB = new Negotiation.TrustRef(regB, reference, subject);
            JsonElement ra = t.GetProperty("ref_a");
            Assert.Equal(ra.GetProperty("body_hex").GetString(), Hex(refA.Bytes()));
            Assert.Equal(ra.GetProperty("head_hex").GetString(), Hex(refA.Head()));
            Assert.Equal(ra.GetProperty("id_hex").GetString(), Hex(refA.Id()));
            JsonElement rb = t.GetProperty("ref_b");
            Assert.Equal(rb.GetProperty("body_hex").GetString(), Hex(refB.Bytes()));
            Assert.Equal(rb.GetProperty("id_hex").GetString(), Hex(refB.Id()));

            // The reference recomputes over the external record; a changed record does not.
            Assert.True(refA.BindsRecord(record));
            Assert.False(refA.BindsRecord(tamperedRecord));
            // Two registries reference the SAME record symmetrically — no relative weight on the wire.
            Assert.Equal(Hex(refA.ReferenceId()), Hex(refB.ReferenceId()));

            // Full-sig verify: recompute confirms; a tampered record is ReferenceMismatch.
            (byte[] seed, byte[] pub) = Key(0x31);
            byte[] obj = Negotiation.SignTrustRef(refA, Alg, seed);
            Negotiation.ResolvedTrustRef resolved = Negotiation.VerifyTrustRef(obj, Cose.PROFILE_PUBLIC, Alg, pub, record);
            Assert.Equal(Hex(reference), Hex(resolved.Reference));
            var ex = Assert.Throws<NaalpException>(() => Negotiation.VerifyTrustRef(obj, Cose.PROFILE_PUBLIC, Alg, pub, tamperedRecord));
            Assert.Equal("ReferenceMismatch", ex.Kind);
        }

        // ---- wire edge cases: strict decode, empty-vs-absent, minimal, look-alike -------------------

        [Fact]
        public void WireEdgeCases()
        {
            JsonElement v = Vector();
            JsonElement ec = v.GetProperty("edge_cases");

            // (1) descending top-level keys are rejected NonCanonical by the strict codec, NegMalformed
            //     by ParseMessage.
            JsonElement koo = ec.GetProperty("keys_out_of_order");
            byte[] canon = Hb(koo.GetProperty("canonical_offer_body_hex").GetString()!);
            byte[] noncanon = Hb(koo.GetProperty("noncanonical_offer_body_hex").GetString()!);
            Cbor.Decode(canon);
            Negotiation.ParseMessage(canon);
            var ce = Assert.Throws<NaalpException>(() => Cbor.Decode(noncanon));
            Assert.Equal("NonCanonical", ce.Kind);
            var pe = Assert.Throws<NaalpException>(() => Negotiation.ParseMessage(noncanon));
            Assert.Equal("NegMalformed", pe.Kind);

            // (2) an empty causes[]/labels[] is distinct-by-id from a populated one; an ABSENT field is
            //     rejected (mandatory field).
            JsonElement causes = ec.GetProperty("empty_vs_absent").GetProperty("causes");
            byte[] emptyCauses = Hb(causes.GetProperty("empty_present").GetProperty("body_hex").GetString()!);
            byte[] oneCause = Hb(causes.GetProperty("one_cause").GetProperty("body_hex").GetString()!);
            Assert.NotEqual(Hex(Negotiation.ParseMessage(emptyCauses).Id()), Hex(Negotiation.ParseMessage(oneCause).Id()));
            var caEx = Assert.Throws<NaalpException>(() =>
                Negotiation.ParseMessage(Hb(causes.GetProperty("absent_field").GetProperty("body_hex").GetString()!)));
            Assert.Equal("NegMalformed", caEx.Kind);

            JsonElement labels = ec.GetProperty("empty_vs_absent").GetProperty("labels");
            byte[] emptyLabels = Hb(labels.GetProperty("empty_present").GetProperty("body_hex").GetString()!);
            byte[] oneLabel = Hb(labels.GetProperty("one_label").GetProperty("body_hex").GetString()!);
            Assert.NotEqual(Hex(Negotiation.ParseLabeledObject(emptyLabels).Id()), Hex(Negotiation.ParseLabeledObject(oneLabel).Id()));
            var laEx = Assert.Throws<NaalpException>(() =>
                Negotiation.ParseLabeledObject(Hb(labels.GetProperty("absent_field").GetProperty("body_hex").GetString()!)));
            Assert.Equal("NegMalformed", laEx.Kind);

            // (3) minimal offer / labeled-object / trust-ref bodies + ids.
            JsonElement min = ec.GetProperty("minimal");
            JsonElement mOffer = min.GetProperty("offer");
            var offer = new Negotiation.Message(Hb(mOffer.GetProperty("negotiation_hex").GetString()!),
                mOffer.GetProperty("role").GetInt64(), mOffer.GetProperty("profile").GetInt64(), new List<byte[]>());
            Assert.Equal(mOffer.GetProperty("body_hex").GetString(), Hex(offer.Bytes()));
            Assert.Equal(mOffer.GetProperty("id_hex").GetString(), Hex(offer.Id()));
            JsonElement mLo = min.GetProperty("labeled_object");
            var lo = new Negotiation.LabeledObject(mLo.GetProperty("effect").GetInt64(), new List<Negotiation.RiskLabel>());
            Assert.Equal(mLo.GetProperty("body_hex").GetString(), Hex(lo.Bytes()));
            Assert.Equal(mLo.GetProperty("id_hex").GetString(), Hex(lo.Id()));
            JsonElement mTr = min.GetProperty("trust_ref");
            var tr = new Negotiation.TrustRef(Array.Empty<byte>(), Array.Empty<byte>(), Array.Empty<byte>());
            Assert.Equal(mTr.GetProperty("body_hex").GetString(), Hex(tr.Bytes()));
            Assert.Equal(mTr.GetProperty("id_hex").GetString(), Hex(tr.Id()));

            // (4) each look-alike body is rejected by the OTHER parser (different shapes).
            JsonElement la = ec.GetProperty("look_alike");
            var l1 = Assert.Throws<NaalpException>(() =>
                Negotiation.ParseMessage(Hb(la.GetProperty("trust_ref_as_message").GetProperty("body_hex").GetString()!)));
            Assert.Equal("NegMalformed", l1.Kind);
            var l2 = Assert.Throws<NaalpException>(() =>
                Negotiation.ParseTrustRef(Hb(la.GetProperty("message_as_trust_ref").GetProperty("body_hex").GetString()!)));
            Assert.Equal("NegMalformed", l2.Kind);
        }

        // ---- full-sig: honest verify, foreign-key BadSignature, closed-set rejections ---------------

        [Fact]
        public void FullSigVerifyAndClosedSets()
        {
            JsonElement v = Vector();
            JsonElement neg = v.GetProperty("negotiation");
            byte[] negId = Hb(neg.GetProperty("negotiation_hex").GetString()!);
            (byte[] seed, byte[] pub) = Key(0x11);
            (_, byte[] foreignPub) = Key(0x22);

            // A signed offer verifies and reconstructs its closed-set fields.
            Negotiation.Message offer = MsgFrom(negId, neg.GetProperty("offer"));
            byte[] offerObj = Negotiation.SignMessage(offer, Alg, seed);
            Negotiation.Message got = Negotiation.VerifyMessage(offerObj, Cose.PROFILE_PUBLIC, Alg, pub);
            Assert.Equal(Negotiation.RoleOffer, got.Role);
            Assert.Equal(Negotiation.ProfileBaseline, got.Profile);
            // A foreign verifier authenticates nothing.
            var bad = Assert.Throws<NaalpException>(() => Negotiation.VerifyMessage(offerObj, Cose.PROFILE_PUBLIC, Alg, foreignPub));
            Assert.Equal("BadSignature", bad.Kind);

            // An unknown role and an unknown profile are rejected after signature-verify.
            Negotiation.Message unkRole = MsgFrom(negId, neg.GetProperty("unknown_role_message"));
            byte[] unkRoleObj = Negotiation.SignMessage(unkRole, Alg, seed);
            var rEx = Assert.Throws<NaalpException>(() => Negotiation.VerifyMessage(unkRoleObj, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("UnknownRole", rEx.Kind);

            Negotiation.Message unkProf = MsgFrom(negId, neg.GetProperty("unknown_profile_offer"));
            byte[] unkProfObj = Negotiation.SignMessage(unkProf, Alg, seed);
            var pEx = Assert.Throws<NaalpException>(() => Negotiation.VerifyMessage(unkProfObj, Cose.PROFILE_PUBLIC, Alg, pub));
            Assert.Equal("UnknownProfile", pEx.Kind);

            // A signed labeled-object verifies; its recognized labels drop the unknown non-critical one.
            var labeled = new Negotiation.LabeledObject(0, CarriedLabels(v));
            byte[] labeledObj = Negotiation.SignLabeledObject(labeled, Alg, seed);
            (Negotiation.LabeledObject lo, List<Negotiation.RiskLabel> recognized) =
                Negotiation.VerifyLabeledObject(labeledObj, Cose.PROFILE_PUBLIC, Alg, pub);
            Assert.Equal(Policy.READ_ONLY, lo.EffectClass());
            Assert.Equal(2, recognized.Count); // codes 1 and 2 are both registered
        }

        // ---- the THREE cross-language signed pins (csharp == Go == Rust, full-sig) ------------------

        [Fact]
        public void CrossLangSignedOfferPin()
        {
            JsonElement v = Vector();
            JsonElement neg = v.GetProperty("negotiation");
            Negotiation.Message offer = MsgFrom(Hb(neg.GetProperty("negotiation_hex").GetString()!), neg.GetProperty("offer"));
            (byte[] seed, _) = Key(0x11);
            byte[] obj = Negotiation.SignMessage(offer, Alg, seed);
            Assert.Equal(PinnedSignedOfferSha384, Hex(Sha384(obj)));
        }

        [Fact]
        public void CrossLangSignedLabeledPin()
        {
            JsonElement v = Vector();
            var labeled = new Negotiation.LabeledObject(
                v.GetProperty("risk").GetProperty("labeled_objects")[0].GetProperty("effect").GetInt64(),
                CarriedLabels(v));
            (byte[] seed, _) = Key(0x11);
            byte[] obj = Negotiation.SignLabeledObject(labeled, Alg, seed);
            Assert.Equal(PinnedSignedLabeledSha384, Hex(Sha384(obj)));
        }

        [Fact]
        public void CrossLangSignedTrustRefPin()
        {
            JsonElement v = Vector();
            JsonElement t = v.GetProperty("trust");
            var refA = new Negotiation.TrustRef(Hb(t.GetProperty("registry_a_hex").GetString()!),
                Hb(t.GetProperty("reference_hex").GetString()!), Hb(t.GetProperty("subject_hex").GetString()!));
            (byte[] seed, _) = Key(0x11);
            byte[] obj = Negotiation.SignTrustRef(refA, Alg, seed);
            Assert.Equal(PinnedSignedTrustRefSha384, Hex(Sha384(obj)));
        }
    }
}
