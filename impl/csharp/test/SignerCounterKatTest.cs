// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;

using Naalp;
using Xunit;

namespace Sh.Bubblefish.Naalp.Tests
{
    /// <summary>
    /// T1.6 per-signer forward-only counter (the OPTIONAL detection ext key 14, NAALP-REQ-120) known-
    /// answer tests for the C# SDK, graded against the independent oracle
    /// (tools/signer_counter_oracle.py -&gt; vectors/signer_counter/cases.json), i.e.
    /// C# == Go == Rust == oracle.
    ///
    /// <para>Mirrors impl/go/envelope/signer_counter_test.go: (1) MATCHES ORACLE (body bytes +
    /// accept/reject verdicts + negatives, including the uint64-max counter), (2) UNDER SIGNATURE
    /// (splice-tamper rejected), (3) READER ROUND TRIP (present-zero distinct from absent),
    /// (4) DETECT MATCHES ORACLE (every scenario in vectors/signer_counter/cases.json#detection),
    /// (5) DETECT ONE SEQUENCE NOT FLAGGED [MUTATION ANCHOR], (6) DETECT TWO CONFLICTING FLAGGED,
    /// (7) DETECT FORWARD-ONLY CONSISTENT NOT FLAGGED, (8) COUNTER ABSENT VALIDATES [MUTATION ANCHOR].
    /// </para>
    ///
    /// <para><see cref="Envelope.Object.BodyMap"/> is <c>internal</c> to the Naalp assembly, so this
    /// separate test assembly cannot call it directly; <see cref="BodyMapFor"/> below reconstructs the
    /// identical map purely from <see cref="Envelope.Object"/>'s PUBLIC fields and the PUBLIC field
    /// constants in Envelope.WireConstants.cs.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~SignerCounterKatTest</c></para>
    /// </summary>
    public sealed class SignerCounterKatTest
    {
        private const int Alg = Cose.ALG_MLDSA65;
        private static readonly byte[] Seed = Range32();

        private static readonly Envelope.KindValidator KindOk = (ch, k) => true;

        private static byte[] Range32()
        {
            byte[] s = new byte[32];
            for (int i = 0; i < s.Length; i++)
            {
                s[i] = (byte)i;
            }
            return s;
        }

        private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

        private static string? FindVector()
        {
            var d = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 10 && d != null; i++)
            {
                string p = Path.Combine(d.FullName, "vectors", "signer_counter", "cases.json");
                if (File.Exists(p))
                {
                    return p;
                }
                d = d.Parent;
            }
            return null;
        }

        private static JsonElement LoadCorpus(out JsonDocument doc)
        {
            string? p = FindVector();
            Assert.True(p != null, "committed signer_counter vector not found from " + AppContext.BaseDirectory);
            doc = JsonDocument.Parse(File.ReadAllText(p!, Encoding.UTF8));
            return doc.RootElement;
        }

        // GetNullableU64 reads a JSON integer that may exceed long.MaxValue (up to uint64 max, e.g.
        // 18446744073709551615) and returns it as the SAME BIT PATTERN in a signed long -- the wire
        // convention this port already uses for Cbor.U.V (see Cbor.cs: "u.V carries the uint64 bit
        // pattern; a value >= 2^63 is a 'negative' long"). Plain JsonElement.GetInt64() throws for such
        // values, so this tries the fast signed path first and falls back to unsigned + reinterpret.
        private static long? GetNullableU64(JsonElement el, string prop)
        {
            if (!el.TryGetProperty(prop, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            if (v.ValueKind == JsonValueKind.String)
            {
                // A counter > 2^53 is carried as a QUOTED decimal string (R12 / NAALP-01-03) so a
                // float64 JSON decoder cannot round it; parse the exact uint64 and keep the same bit
                // pattern in a signed long (u.V's convention -- see Cbor.cs).
                return unchecked((long)ulong.Parse(v.GetString()!, System.Globalization.CultureInfo.InvariantCulture));
            }
            if (v.TryGetInt64(out long l))
            {
                return l;
            }
            ulong u = v.GetUInt64();
            return unchecked((long)u);
        }

        // baseObject builds the shared base object (fields 2..10) from LOGICAL fields, with an optional
        // signer/body override -- never from the oracle hex, so a constant encoder diverges.
        private static Envelope.Object BaseObject(JsonElement baseObj, string? signerHexOverride, string? bodyStrOverride)
        {
            long kind = baseObj.GetProperty("kind").GetInt64();
            long channel = baseObj.GetProperty("channel").GetInt64();
            long tier = baseObj.GetProperty("tier").GetInt64();
            string signerHex = signerHexOverride ?? baseObj.GetProperty("signer_hex").GetString()!;
            byte[] signer = Convert.FromHexString(signerHex);
            long created = baseObj.GetProperty("created").GetInt64();
            long effect = baseObj.GetProperty("effect").GetInt64();
            var causes = new List<byte[]>();
            foreach (JsonElement c in baseObj.GetProperty("causes_hex").EnumerateArray())
            {
                causes.Add(Convert.FromHexString(c.GetString()!));
            }
            long profile = baseObj.GetProperty("profile").GetInt64();
            string bodyStr = bodyStrOverride ?? baseObj.GetProperty("body_str").GetString()!;
            return new Envelope.Object(
                kind: kind, channel: channel, signer: signer, created: created, effect: effect,
                body: new Cbor.T(bodyStr), tier: tier, profile: profile, causes: causes);
        }

        // applyPlacement applies the case's counter placement -- the ONLY variable per case.
        private static void ApplyPlacement(Envelope.Object o, string placement, long? counter)
        {
            switch (placement)
            {
                case "ext":
                    o.SetSignerCounter(counter!.Value);
                    break;
                case "cext":
                    // the counter placed in the CRITICAL map is an unrecognized critical extension.
                    o.Cext = new Cbor.M(new List<Cbor.Pair>
                    {
                        new Cbor.Pair(new Cbor.U(Envelope.SIGNER_COUNTER_KEY), new Cbor.U(counter!.Value)),
                    });
                    break;
                case "ext_empty":
                    o.Ext = new Cbor.M(new List<Cbor.Pair>()); // present but empty (no counter)
                    break;
                case "absent":
                    break; // no ext, no cext
                default:
                    throw new InvalidOperationException("unknown placement " + placement);
            }
        }

        private static Cbor.M BodyMapFor(Envelope.Object o, bool includeId)
        {
            var pairs = new List<Cbor.Pair>(14);
            if (includeId)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldId), new Cbor.B(o.Id!)));
            }
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldKind), new Cbor.U(o.Kind)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldChannel), new Cbor.U(o.Channel)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldTier), new Cbor.U(o.Tier)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldSigner), new Cbor.B(o.Signer)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldCreated), new Cbor.U(o.Created)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldEffect), new Cbor.U(o.Effect)));
            var causeItems = new List<Cbor.Value>(o.Causes.Count);
            foreach (byte[] c in o.Causes)
            {
                causeItems.Add(new Cbor.B(c));
            }
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldCauses), new Cbor.A(causeItems)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldProfile), new Cbor.U(o.Profile)));
            pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldBody), o.Body));
            if (o.Ext != null)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldExt), o.Ext));
            }
            if (o.Cext != null)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldCext), o.Cext));
            }
            if (o.Audience.Length != 0)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldAudience), new Cbor.T(o.Audience)));
            }
            if (o.Suite != 0)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(Envelope.FieldSuite), new Cbor.U(o.Suite)));
            }
            return new Cbor.M(pairs);
        }

        [Fact]
        public void MatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                long corpusKey = root.GetProperty("counter_key").GetInt64();
                Assert.Equal((long)Envelope.SIGNER_COUNTER_KEY, corpusKey);

                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                foreach (JsonElement tc in root.GetProperty("cases").EnumerateArray())
                {
                    string name = tc.GetProperty("name").GetString()!;
                    string placement = tc.GetProperty("placement").GetString()!;
                    long? counter = GetNullableU64(tc, "counter");
                    string? signerHex = tc.TryGetProperty("signer_hex", out JsonElement shv) ? shv.GetString() : null;
                    string? bodyStr = tc.TryGetProperty("body_str", out JsonElement bsv) ? bsv.GetString() : null;

                    Envelope.Object o = BaseObject(baseObj, signerHex, bodyStr);
                    ApplyPlacement(o, placement, counter);

                    // byte parity: body-without-id, content id, full body.
                    string bodyNoIdHex = tc.GetProperty("body_no_id_hex").GetString()!;
                    Assert.True(bodyNoIdHex == Hex(Cbor.Encode(BodyMapFor(o, false))), name + ": body-no-id");

                    byte[] cid = o.ContentId();
                    string contentIdHex = tc.GetProperty("content_id_hex").GetString()!;
                    Assert.True(contentIdHex == Hex(cid), name + ": content-id");

                    o.Id = cid;
                    string fullHex = tc.GetProperty("full_hex").GetString()!;
                    Assert.True(fullHex == Hex(Cbor.Encode(BodyMapFor(o, true))), name + ": full-body");

                    // verdict: sign for real + verify offline; assert accept vs the named error.
                    Envelope.Object o2 = BaseObject(baseObj, signerHex, bodyStr);
                    ApplyPlacement(o2, placement, counter);
                    byte[] signed = Envelope.Sign(o2, Alg, Seed);

                    string expect = tc.GetProperty("expect").GetString()!;
                    if (expect == "accept")
                    {
                        Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed);
                        (long seq, bool present) = got.SignerCounter();
                        bool wantPresent = tc.GetProperty("present").GetBoolean();
                        Assert.True(present == wantPresent, name + ": SignerCounter present");
                        if (present)
                        {
                            Assert.True(counter != null && seq == counter.Value, name + ": SignerCounter value");
                        }
                    }
                    else
                    {
                        NaalpException ex = Assert.Throws<NaalpException>(() =>
                            Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed));
                        Assert.True(expect == ex.Kind, name + ": verdict error, got " + ex.Kind);
                    }
                }

                // non-canonical counter bodies (ext keys out of order) are rejected at the CBOR layer.
                // prot depends only on (alg, signer, profile); the base object's signer/profile matches
                // the fixed "SIGNER_A"/1 the oracle's negative payload was built against.
                if (root.TryGetProperty("negatives", out JsonElement negatives))
                {
                    Envelope.Object protoObj = BaseObject(baseObj, null, null);
                    byte[] anySigned = Envelope.Sign(protoObj, Alg, Seed);
                    byte[][] parts = Cose.ParseSign1Raw(anySigned);
                    byte[] prot = parts[0];

                    foreach (JsonElement neg in negatives.EnumerateArray())
                    {
                        string negName = neg.GetProperty("name").GetString()!;
                        byte[] payload = Convert.FromHexString(neg.GetProperty("payload_hex").GetString()!);
                        byte[] forged = Cose.CoseSign1(Alg, Seed, prot, payload);
                        string negExpect = neg.GetProperty("expect").GetString()!;
                        NaalpException ex = Assert.Throws<NaalpException>(() =>
                            Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, forged));
                        Assert.True(negExpect == ex.Kind, "negative_" + negName + ": verdict error, got " + ex.Kind);
                    }
                }
            }
        }

        /// <summary>
        /// Proves the counter is folded into the SIGNER's COSE_Sign1 signed input (ext, field 11, is
        /// part of the signed body): flipping the counter value in a signed object's payload breaks
        /// verification. A signer-signed (not ledger-signed) counter is the whole point.
        /// </summary>
        [Fact]
        public void UnderSignature()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                Envelope.Object o = BaseObject(baseObj, null, null);
                o.SetSignerCounter(5);
                byte[] signed = Envelope.Sign(o, Alg, Seed);

                // baseline: the signed object verifies and reads back counter 5.
                Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed);
                (long seq0, bool present0) = got.SignerCounter();
                Assert.True(present0 && seq0 == 5, "counter read-back");

                // tamper: change the counter to 6 and re-encode the body WITHOUT re-signing; the object
                // must be rejected (the content id no longer matches the signed body / the signature no
                // longer covers it).
                Envelope.Object tampered = BaseObject(baseObj, null, null);
                tampered.SetSignerCounter(6);
                tampered.Id = o.Id; // keep the original (counter=5) content id -- a splice, not a re-sign
                byte[] payload = Cbor.Encode(BodyMapFor(tampered, true));
                byte[][] parts = Cose.ParseSign1Raw(signed);
                byte[] prot = parts[0];
                byte[] origSig = parts[2];
                byte[] forged = Cose.AssembleSign1Raw(prot, payload, origSig);
                Assert.Throws<NaalpException>(() =>
                    Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, forged));
            }
        }

        /// <summary>
        /// Proves SignerCounter()/SetSignerCounter() carry the value, that the field is OPTIONAL (a
        /// fresh object has none), and that a present counter of value 0 reads back present (present is
        /// keyed on the key, not the value).
        /// </summary>
        [Fact]
        public void ReaderRoundTrip()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                Envelope.Object o = BaseObject(baseObj, null, null);

                (long _, bool present0) = o.SignerCounter();
                Assert.False(present0, "fresh object must have no counter");

                o.SetSignerCounter(42);
                (long seq1, bool present1) = o.SignerCounter();
                Assert.True(present1 && seq1 == 42, "counter read back wrong");

                o.SetSignerCounter(0); // present with value zero
                (long seq2, bool present2) = o.SignerCounter();
                Assert.True(present2 && seq2 == 0, "present-zero counter must read back present");
            }
        }

        /// <summary>
        /// Grades DetectSignerDuplication over every scenario in the independent oracle: the impl
        /// reconstructs the presented set and MUST reproduce the oracle's exact findings (signer,
        /// counter, and the SET of surfaced content ids).
        /// </summary>
        [Fact]
        public void DetectMatchesOracle()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                JsonElement scenarios = root.GetProperty("detection").GetProperty("scenarios");

                foreach (JsonElement sc in scenarios.EnumerateArray())
                {
                    string scName = sc.GetProperty("name").GetString()!;
                    var objs = new List<Envelope.Object>();
                    foreach (JsonElement ro in sc.GetProperty("objects").EnumerateArray())
                    {
                        string signerHex = ro.GetProperty("signer_hex").GetString()!;
                        string bodyStr = ro.GetProperty("body_str").GetString()!;
                        long? counter = GetNullableU64(ro, "counter");
                        Envelope.Object o = BaseObject(baseObj, signerHex, bodyStr);
                        if (counter != null)
                        {
                            o.SetSignerCounter(counter.Value);
                        }
                        byte[] id = o.ContentId();
                        string wantId = ro.GetProperty("content_id_hex").GetString()!;
                        Assert.True(wantId == Hex(id), scName + ": scenario object content-id");
                        objs.Add(o);
                    }

                    List<Envelope.DuplicationFinding> findings = EnvelopeSignerCounterExtensions.DetectSignerDuplication(objs);
                    JsonElement expect = sc.GetProperty("expect");
                    int wantCount = 0;
                    foreach (JsonElement _ in expect.EnumerateArray())
                    {
                        wantCount++;
                    }
                    Assert.True(findings.Count == wantCount, scName + ": findings count got " + findings.Count + " want " + wantCount);

                    int i = 0;
                    foreach (JsonElement want in expect.EnumerateArray())
                    {
                        Envelope.DuplicationFinding got = findings[i];
                        string wantSignerHex = want.GetProperty("signer_hex").GetString()!;
                        Assert.True(wantSignerHex == Hex(got.Signer), scName + ": finding " + i + " signer");
                        long wantCounter = GetNullableU64(want, "counter")!.Value;
                        Assert.True(wantCounter == got.Counter, scName + ": finding " + i + " counter");
                        var wantIds = new List<string>();
                        foreach (JsonElement idh in want.GetProperty("ids_hex").EnumerateArray())
                        {
                            wantIds.Add(idh.GetString()!);
                        }
                        Assert.True(wantIds.Count == got.Ids.Count, scName + ": finding " + i + " ids count");
                        for (int j = 0; j < wantIds.Count; j++)
                        {
                            Assert.True(wantIds[j] == Hex(got.Ids[j]), scName + ": finding " + i + " id " + j);
                        }
                        i++;
                    }
                }
            }
        }

        /// <summary>
        /// MUTATION ANCHOR for DetectSignerDuplication: a single sequence (one object per value) MUST
        /// NOT be flagged -- detection requires two conflicting sequences to physically meet. Relaxing
        /// the "idset.Count &lt; 2" guard to "&lt; 1" (flag from one) flips this test pass-&gt;fail;
        /// that is the whole detection-not-prevention line.
        /// </summary>
        [Fact]
        public void DetectOneSequenceNotFlagged()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");

                Envelope.Object one = BaseObject(baseObj, null, "holder");
                one.SetSignerCounter(5);
                Assert.Empty(EnvelopeSignerCounterExtensions.DetectSignerDuplication(new[] { one }));

                var seqObjs = new List<Envelope.Object>();
                string[] bodies = { "s1", "s2", "s3" };
                for (int i = 0; i < bodies.Length; i++)
                {
                    Envelope.Object o = BaseObject(baseObj, null, bodies[i]);
                    o.SetSignerCounter((long)(i + 1));
                    seqObjs.Add(o);
                }
                Assert.Empty(EnvelopeSignerCounterExtensions.DetectSignerDuplication(seqObjs));
            }
        }

        /// <summary>
        /// Two DISTINCT objects, SAME signer id, SAME counter value, presented TOGETHER -&gt; flagged
        /// once, surfacing BOTH content ids. This is the duplication fingerprint and it is only
        /// observable because both objects are present.
        /// </summary>
        [Fact]
        public void DetectTwoConflictingFlagged()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");

                Envelope.Object holder = BaseObject(baseObj, null, "holder");
                holder.SetSignerCounter(5);
                Envelope.Object thief = BaseObject(baseObj, null, "thief");
                thief.SetSignerCounter(5);

                List<Envelope.DuplicationFinding> f = EnvelopeSignerCounterExtensions.DetectSignerDuplication(new[] { holder, thief });
                Assert.True(f.Count == 1, "two conflicting sequences must be flagged once, got " + f.Count);
                Assert.Equal(5, f[0].Counter);
                Assert.True(f[0].Ids.Count == 2, "both conflicting content ids must be surfaced, got " + f[0].Ids.Count);

                byte[] hid = holder.ContentId();
                byte[] tid = thief.ContentId();
                var surfaced = new HashSet<string>();
                foreach (byte[] id in f[0].Ids)
                {
                    surfaced.Add(Hex(id));
                }
                Assert.Contains(Hex(hid), surfaced);
                Assert.Contains(Hex(tid), surfaced);
            }
        }

        /// <summary>
        /// Two objects from one signer at DIFFERENT (forward-only consistent) positions are not
        /// flagged; nor are two different signers at one position.
        /// </summary>
        [Fact]
        public void DetectForwardOnlyConsistentNotFlagged()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");

                Envelope.Object a5 = BaseObject(baseObj, null, "holder");
                a5.SetSignerCounter(5);
                Envelope.Object a6 = BaseObject(baseObj, null, "next");
                a6.SetSignerCounter(6);
                Assert.Empty(EnvelopeSignerCounterExtensions.DetectSignerDuplication(new[] { a5, a6 }));

                // per-signer: SIGNER_B at position 5 does not conflict with SIGNER_A at position 5.
                Envelope.Object b5 = BaseObject(baseObj, "5349474e45525f42", "other");
                b5.SetSignerCounter(5);
                Assert.Empty(EnvelopeSignerCounterExtensions.DetectSignerDuplication(new[] { a5, b5 }));
            }
        }

        /// <summary>
        /// MUTATION ANCHOR for optionality: an object carrying NO counter Signs and Verifies. Making the
        /// field mandatory (e.g. adding a reject-if-absent check to Verify) flips this test pass-&gt;fail.
        /// </summary>
        [Fact]
        public void CounterAbsentValidates()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                Envelope.Object o = BaseObject(baseObj, null, null);
                (long _, bool present0) = o.SignerCounter();
                Assert.False(present0, "object built without a counter must have none");

                byte[] signed = Envelope.Sign(o, Alg, Seed);
                Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed);
                (long _, bool present1) = got.SignerCounter();
                Assert.False(present1, "verified object must report no counter");
            }
        }
    }
}
