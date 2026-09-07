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
    /// T1.3 recheck procedure (the OPTIONAL checkable-minimum ext/cext key 13, NAALP-REQ-110/111)
    /// known-answer tests for the C# SDK, graded against the independent oracle
    /// (tools/recheck_oracle.py -&gt; vectors/recheck/cases.json), i.e. C# == Go == Rust == oracle.
    ///
    /// <para>Mirrors impl/go/envelope/envelope_test.go's recheck section: (1) MATCHES ORACLE (body
    /// bytes + accept/reject verdicts + negatives), (2) REJECT PATH IS REAL [MUTATION ANCHOR: a
    /// critical unknown procedure id must reject; a known critical / unknown non-critical procedure
    /// must NOT], (3) READER ROUND TRIP [also proves cext-over-ext precedence].</para>
    ///
    /// <para><see cref="Envelope.Object.BodyMap"/> is <c>internal</c> to the Naalp assembly, so this
    /// separate test assembly cannot call it directly; <see cref="BodyMapFor"/> below reconstructs the
    /// identical map purely from <see cref="Envelope.Object"/>'s PUBLIC fields and the PUBLIC field
    /// constants in Envelope.WireConstants.cs -- deterministic CBOR canonically sorts map keys
    /// regardless of insertion order, so this reproduces byte-identical output to the impl's own
    /// BodyMap.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~RecheckKatTest</c></para>
    /// </summary>
    public sealed class RecheckKatTest
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
                string p = Path.Combine(d.FullName, "vectors", "recheck", "cases.json");
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
            Assert.True(p != null, "committed recheck vector not found from " + AppContext.BaseDirectory);
            doc = JsonDocument.Parse(File.ReadAllText(p!, Encoding.UTF8));
            return doc.RootElement;
        }

        private static long? GetNullableLong(JsonElement el, string prop)
        {
            if (!el.TryGetProperty(prop, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            return v.GetInt64();
        }

        // baseObject builds the shared base object (fields 2..10) from LOGICAL fields -- never from the
        // oracle hex, so a constant/field-ignoring encoder diverges from the pinned bytes.
        private static Envelope.Object BaseObject(JsonElement baseObj)
        {
            long kind = baseObj.GetProperty("kind").GetInt64();
            long channel = baseObj.GetProperty("channel").GetInt64();
            long tier = baseObj.GetProperty("tier").GetInt64();
            byte[] signer = Convert.FromHexString(baseObj.GetProperty("signer_hex").GetString()!);
            long created = baseObj.GetProperty("created").GetInt64();
            long effect = baseObj.GetProperty("effect").GetInt64();
            var causes = new List<byte[]>();
            foreach (JsonElement c in baseObj.GetProperty("causes_hex").EnumerateArray())
            {
                causes.Add(Convert.FromHexString(c.GetString()!));
            }
            long profile = baseObj.GetProperty("profile").GetInt64();
            string bodyStr = baseObj.GetProperty("body_str").GetString()!;
            return new Envelope.Object(
                kind: kind, channel: channel, signer: signer, created: created, effect: effect,
                body: new Cbor.T(bodyStr), tier: tier, profile: profile, causes: causes);
        }

        // applyPlacement applies the case's recheck placement -- the ONLY variable per case.
        private static void ApplyPlacement(Envelope.Object o, string placement, long? procId)
        {
            switch (placement)
            {
                case "cext":
                    o.SetRecheck(procId!.Value, true);
                    break;
                case "ext":
                    o.SetRecheck(procId!.Value, false);
                    break;
                case "ext_empty":
                    o.Ext = new Cbor.M(new List<Cbor.Pair>()); // present but empty (no recheck)
                    break;
                case "absent":
                    break; // no ext, no cext
                default:
                    throw new InvalidOperationException("unknown placement " + placement);
            }
        }

        // bodyMapFor reconstructs Envelope.Object's internal BodyMap using ONLY public members (see the
        // class doc comment above).
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
                long corpusKey = root.GetProperty("recheck_key").GetInt64();
                Assert.Equal((long)Envelope.RECHECK_KEY, corpusKey);

                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                foreach (JsonElement tc in root.GetProperty("cases").EnumerateArray())
                {
                    string name = tc.GetProperty("name").GetString()!;
                    string placement = tc.GetProperty("placement").GetString()!;
                    long? procId = GetNullableLong(tc, "procedure_id");

                    Envelope.Object o = BaseObject(baseObj);
                    ApplyPlacement(o, placement, procId);

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
                    Envelope.Object o2 = BaseObject(baseObj);
                    ApplyPlacement(o2, placement, procId);
                    byte[] signed = Envelope.Sign(o2, Alg, Seed);

                    string expect = tc.GetProperty("expect").GetString()!;
                    if (expect == "accept")
                    {
                        Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed);
                        (long rid, bool present, bool critical) = got.Recheck();
                        bool wantPresent = tc.GetProperty("present").GetBoolean();
                        Assert.True(present == wantPresent, name + ": present");
                        if (present)
                        {
                            Assert.True(procId != null && rid == procId.Value, name + ": recheck id");
                            bool wantCritical = tc.GetProperty("critical").GetBoolean();
                            Assert.True(critical == wantCritical, name + ": critical");
                        }
                    }
                    else
                    {
                        NaalpException ex = Assert.Throws<NaalpException>(() =>
                            Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed));
                        Assert.True(expect == ex.Kind, name + ": verdict error, got " + ex.Kind);
                    }
                }

                // non-canonical recheck bodies (keys out of order) are rejected at the CBOR layer. prot
                // depends only on (alg, signer, profile), never on the payload, so deriving it from a
                // fresh, placement-free base object reproduces exactly the protected header the
                // oracle's negative payload was built against (base signer/profile == "SIGNER_A"/1).
                if (root.TryGetProperty("negatives", out JsonElement negatives))
                {
                    Envelope.Object protoObj = BaseObject(baseObj);
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
        /// MUTATION ANCHOR: a CRITICAL recheck naming an UNKNOWN procedure id MUST be rejected with
        /// UnknownCriticalExt. If the Verify recheck branch is mutated to accept, this test flips
        /// pass-&gt;fail. A known critical procedure and a non-critical unknown procedure both verify,
        /// proving the reject is specific to unknown-under-critical and not a blanket denial.
        /// </summary>
        [Fact]
        public void RejectPathIsReal()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                Envelope.Object criticalUnknown = BaseObject(baseObj);
                criticalUnknown.SetRecheck(99, true); // unknown id, critical
                byte[] su = Envelope.Sign(criticalUnknown, Alg, Seed);
                NaalpException exU = Assert.Throws<NaalpException>(() =>
                    Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, su));
                Assert.Equal("UnknownCriticalExt", exU.Kind);

                Envelope.Object criticalKnown = BaseObject(baseObj);
                criticalKnown.SetRecheck(Envelope.RECHECK_WALK_CAUSES, true); // known id, critical
                byte[] sk = Envelope.Sign(criticalKnown, Alg, Seed);
                Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, sk); // must NOT throw

                Envelope.Object nonCritUnknown = BaseObject(baseObj);
                nonCritUnknown.SetRecheck(99, false); // unknown id, non-critical -> ignored
                byte[] sn = Envelope.Sign(nonCritUnknown, Alg, Seed);
                Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, sn); // must NOT throw
            }
        }

        /// <summary>
        /// Proves Recheck()/SetRecheck() carry the id and criticality, and that cext (critical) takes
        /// precedence over ext (non-critical) when both name the key.
        /// </summary>
        [Fact]
        public void ReaderRoundTrip()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                Envelope.Object o = BaseObject(baseObj);

                (long _, bool present0, bool _) = o.Recheck();
                Assert.False(present0, "fresh object must have no recheck");

                o.SetRecheck(Envelope.RECHECK_VERIFY_COSE_SIGN1, false);
                (long id1, bool present1, bool critical1) = o.Recheck();
                Assert.True(present1 && id1 == Envelope.RECHECK_VERIFY_COSE_SIGN1 && !critical1,
                    "non-critical recheck read back wrong");

                o.SetRecheck(Envelope.RECHECK_REPLAY_CONSUME_CHECK, true); // critical wins over the ext entry
                (long id2, bool present2, bool critical2) = o.Recheck();
                Assert.True(present2 && id2 == Envelope.RECHECK_REPLAY_CONSUME_CHECK && critical2,
                    "critical recheck must take precedence");
            }
        }

        /// <summary>Direct unit coverage of the closed registry boundaries (1..4 known; 0 and 5 not).</summary>
        [Fact]
        public void IsKnownRecheckProcedureBoundaries()
        {
            Assert.False(Envelope.IsKnownRecheckProcedure(0));
            Assert.True(Envelope.IsKnownRecheckProcedure(1));
            Assert.True(Envelope.IsKnownRecheckProcedure(2));
            Assert.True(Envelope.IsKnownRecheckProcedure(3));
            Assert.True(Envelope.IsKnownRecheckProcedure(4));
            Assert.False(Envelope.IsKnownRecheckProcedure(5));
        }
    }
}
