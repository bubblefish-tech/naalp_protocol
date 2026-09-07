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
    /// NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4)
    /// known-answer tests for the C# SDK, graded against the independent oracle
    /// (tools/producing_boundary_oracle.py -&gt; vectors/producing_boundary/cases.json), i.e.
    /// C# == Go == Rust == Python == oracle.
    ///
    /// <para>Five properties, mirroring impl/go/envelope/producing_boundary_test.go and
    /// impl/python/tests/test_producing_boundary.py, all mutation-surviving:
    /// (1) MATCHES ORACLE, (2) UNDER SIGNATURE, (3) READER ROUND-TRIP,
    /// (4) MALFORMED IGNORED [MUTATION ANCHOR], (5) CEXT REJECTED [MUTATION ANCHOR].</para>
    ///
    /// <para><see cref="Envelope.Object.BodyMap"/> is <c>internal</c> to the Naalp assembly, so this
    /// test project (a separate assembly) cannot call it directly; <see cref="BodyMapFor"/> below
    /// reconstructs the identical map purely from <see cref="Envelope.Object"/>'s PUBLIC fields and the
    /// PUBLIC field-number constants in Envelope.WireConstants.cs. Deterministic CBOR canonically sorts
    /// map keys regardless of insertion order (Cbor.cs, Array.Sort by encoded-key bytes), so this
    /// reproduces byte-identical output to the impl's own BodyMap.</para>
    ///
    /// <para>Run: <c>dotnet test test/Bubblefish.Naalp.Tests.csproj -c Release --filter FullyQualifiedName~ProducingBoundary</c></para>
    /// </summary>
    public sealed class ProducingBoundaryKatTest
    {
        private const int Alg = Cose.ALG_MLDSA65;
        private static readonly byte[] Seed = Range32();   // a LOCAL test signing seed -- the verdict is
                                                             // a sign+verify round-trip, not a reproduction
                                                             // of the oracle's signature (full_hex is the
                                                             // object BODY, not a signed COSE object, so
                                                             // byte-parity needs no signing).

        private static readonly byte[] BoundaryX = Convert.FromHexString("424f554e444152595f58");
        private static readonly byte[] BoundaryY = Convert.FromHexString("4f524947494e5f59");

        private static readonly Envelope.KindValidator KindOk = (ch, k) => true;

        // the producing-boundary value sub-map WIRE keys (§2.5.4), used to build ext/cext DIRECTLY so
        // the test grades the impl against the oracle's independent wire layout, not the impl's own
        // private constants.
        private const int KBoundary = 1;
        private const int KKind = 2;
        private const int KReporting = 3;

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
                string p = Path.Combine(d.FullName, "vectors", "producing_boundary", "cases.json");
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
            Assert.True(p != null, "committed producing_boundary vector not found from " + AppContext.BaseDirectory);
            doc = JsonDocument.Parse(File.ReadAllText(p!, Encoding.UTF8));
            return doc.RootElement;
        }

        private static string? GetNullableString(JsonElement el, string prop)
        {
            if (!el.TryGetProperty(prop, out JsonElement v) || v.ValueKind == JsonValueKind.Null)
            {
                return null;
            }
            return v.GetString();
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
        // oracle hex, so a constant encoder diverges from the pinned bytes.
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

        // applyPlacement builds the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields --
        // the ONLY variable per case -- reproducing the oracle bytes for well-formed AND malformed
        // values (the malformed cases cannot be built via SetProducingBoundary by design, so they are
        // constructed here).
        private static void ApplyPlacement(Envelope.Object o, JsonElement tc)
        {
            string placement = tc.GetProperty("placement").GetString()!;
            if (placement == "absent")
            {
                return;
            }
            var sub = new List<Cbor.Pair>();
            string? boundaryHex = GetNullableString(tc, "boundary_hex");
            if (boundaryHex != null)
            {
                sub.Add(new Cbor.Pair(new Cbor.U(KBoundary), new Cbor.B(Convert.FromHexString(boundaryHex))));
            }
            long? kind = GetNullableLong(tc, "kind");
            if (kind != null)
            {
                sub.Add(new Cbor.Pair(new Cbor.U(KKind), new Cbor.U(kind.Value)));
            }
            string? reportingHex = GetNullableString(tc, "reporting_hex");
            if (reportingHex != null)
            {
                sub.Add(new Cbor.Pair(new Cbor.U(KReporting), new Cbor.B(Convert.FromHexString(reportingHex))));
            }
            var ext = new Cbor.M(new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(sub)),
            });
            if (placement == "ext")
            {
                o.Ext = ext;
            }
            else if (placement == "cext")
            {
                o.Cext = ext;
            }
            else
            {
                throw new InvalidOperationException("unknown placement " + placement);
            }
        }

        // bodyMapFor reconstructs Envelope.Object's internal BodyMap using ONLY public members (see the
        // class doc comment above for why this is needed from a separate test assembly).
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
                long corpusKey = root.GetProperty("producing_boundary_key").GetInt64();
                Assert.Equal((long)Envelope.PRODUCING_BOUNDARY_KEY, corpusKey);

                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                foreach (JsonElement tc in root.GetProperty("cases").EnumerateArray())
                {
                    string name = tc.GetProperty("name").GetString()!;

                    Envelope.Object o = BaseObject(baseObj);
                    ApplyPlacement(o, tc);

                    // byte parity: body-without-id, content id, full body (all pre-signature).
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
                    ApplyPlacement(o2, tc);
                    byte[] signed = Envelope.Sign(o2, Alg, Seed);

                    string expect = tc.GetProperty("expect").GetString()!;
                    if (expect == "accept")
                    {
                        Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed);
                        (Envelope.ProducingBoundary? pb, bool present) = got.ProducingBoundary();
                        bool wantPresent = tc.GetProperty("present").GetBoolean();
                        Assert.True(present == wantPresent, name + ": present");
                        if (present)
                        {
                            JsonElement surfaced = tc.GetProperty("surfaced");
                            long wantKind = surfaced.GetProperty("kind").GetInt64();
                            Assert.True(wantKind == pb!.Kind, name + ": kind");
                            string wantBoundaryHex = surfaced.GetProperty("boundary_hex").GetString()!;
                            Assert.True(wantBoundaryHex == Hex(pb.Boundary), name + ": boundary");
                            string wantReportingHex = GetNullableString(surfaced, "reporting_hex") ?? "";
                            Assert.True(wantReportingHex == Hex(pb.Reporting ?? Array.Empty<byte>()), name + ": reporting");
                        }
                    }
                    else
                    {
                        NaalpException ex = Assert.Throws<NaalpException>(() =>
                            Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed));
                        Assert.True(expect == ex.Kind, name + ": verdict error, got " + ex.Kind);
                    }
                }

                // non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR
                // layer. prot depends only on (alg, signer, profile), never on the payload, so deriving
                // it from a fresh, placement-free base object reproduces exactly the protected header the
                // oracle's negative payload was built against.
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

        [Fact]
        public void UnderSignature()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                Envelope.Object o = BaseObject(baseObj);
                o.SetProducingBoundary(new Envelope.ProducingBoundary(BoundaryX, Envelope.PRODUCING_BOUNDARY_OBSERVED));
                byte[] signed = Envelope.Sign(o, Alg, Seed);

                // baseline: the signed object verifies and reads back the disclosure.
                Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed);
                (Envelope.ProducingBoundary? pb0, bool present0) = got.ProducingBoundary();
                Assert.True(present0 && pb0!.Kind == Envelope.PRODUCING_BOUNDARY_OBSERVED, "read-back");

                // tamper: change boundary, keep the original id, reuse the original signature (a splice).
                Envelope.Object tampered = BaseObject(baseObj);
                tampered.SetProducingBoundary(new Envelope.ProducingBoundary(BoundaryY, Envelope.PRODUCING_BOUNDARY_OBSERVED));
                tampered.Id = o.Id; // keep original content id -- a splice, not a re-sign
                byte[] payload = Cbor.Encode(BodyMapFor(tampered, true));
                byte[][] parts = Cose.ParseSign1Raw(signed);
                byte[] prot = parts[0];
                byte[] origSig = parts[2];
                byte[] forged = Cose.AssembleSign1Raw(prot, payload, origSig);
                Assert.Throws<NaalpException>(() => Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, forged));
            }
        }

        [Fact]
        public void ReaderRoundTrip()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");

                Envelope.Object o = BaseObject(baseObj);
                (Envelope.ProducingBoundary? _, bool present0) = o.ProducingBoundary();
                Assert.False(present0, "fresh object must have no producing-boundary disclosure");

                o.SetProducingBoundary(new Envelope.ProducingBoundary(BoundaryX, Envelope.PRODUCING_BOUNDARY_REPORTED, BoundaryY));
                (Envelope.ProducingBoundary? pb1, bool present1) = o.ProducingBoundary();
                Assert.True(present1);
                Assert.Equal(Envelope.PRODUCING_BOUNDARY_REPORTED, pb1!.Kind);
                Assert.Equal(Hex(BoundaryX), Hex(pb1.Boundary));
                Assert.Equal(Hex(BoundaryY), Hex(pb1.Reporting!));

                // the setter drops a reporting-boundary under observed: read-back has no reporting.
                o.SetProducingBoundary(new Envelope.ProducingBoundary(BoundaryX, Envelope.PRODUCING_BOUNDARY_OBSERVED, BoundaryY));
                (Envelope.ProducingBoundary? pb2, bool present2) = o.ProducingBoundary();
                Assert.True(present2);
                Assert.Equal(Envelope.PRODUCING_BOUNDARY_OBSERVED, pb2!.Kind);
                Assert.Null(pb2.Reporting);
            }
        }

        /// <summary>
        /// MUTATION ANCHOR: dropping the reporting-under-observed check in
        /// <see cref="EnvelopeProducingBoundaryExtensions.ProducingBoundary"/> flips present false-&gt;true
        /// and this test pass-&gt;fail; that check is the observer-relays-from-no-one invariant.
        /// </summary>
        [Fact]
        public void MalformedIgnored()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                Envelope.Object o = BaseObject(baseObj);
                // malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
                o.Ext = new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(new List<Cbor.Pair>
                    {
                        new Cbor.Pair(new Cbor.U(KBoundary), new Cbor.B(BoundaryX)),
                        new Cbor.Pair(new Cbor.U(KKind), new Cbor.U(Envelope.PRODUCING_BOUNDARY_OBSERVED)),
                        new Cbor.Pair(new Cbor.U(KReporting), new Cbor.B(BoundaryY)),
                    })),
                });
                byte[] signed = Envelope.Sign(o, Alg, Seed);
                Envelope.Object got = Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed); // must NOT throw (may-ignore)
                (Envelope.ProducingBoundary? _, bool present) = got.ProducingBoundary();
                Assert.False(present, "a malformed disclosure (reporting under observed) must NOT be surfaced");
            }
        }

        /// <summary>
        /// MUTATION ANCHOR: the disclosure in the CRITICAL cext map (field 12) is an unrecognized
        /// critical extension -&gt; UnknownCriticalExt, fail-closed. A disclosure must never masquerade
        /// as a must-understand gate.
        /// </summary>
        [Fact]
        public void CextRejected()
        {
            JsonElement root = LoadCorpus(out JsonDocument doc);
            using (doc)
            {
                JsonElement baseObj = root.GetProperty("base_object");
                byte[] pk = Cose.MldsaKeygen("ML-DSA-65", Seed);

                Envelope.Object o = BaseObject(baseObj);
                o.Cext = new Cbor.M(new List<Cbor.Pair>
                {
                    new Cbor.Pair(new Cbor.U(Envelope.PRODUCING_BOUNDARY_KEY), new Cbor.M(new List<Cbor.Pair>
                    {
                        new Cbor.Pair(new Cbor.U(KBoundary), new Cbor.B(BoundaryX)),
                        new Cbor.Pair(new Cbor.U(KKind), new Cbor.U(Envelope.PRODUCING_BOUNDARY_OBSERVED)),
                    })),
                });
                byte[] signed = Envelope.Sign(o, Alg, Seed);
                NaalpException ex = Assert.Throws<NaalpException>(() =>
                    Envelope.Verify(Cose.PROFILE_PUBLIC, Alg, pk, KindOk, signed));
                Assert.Equal("UnknownCriticalExt", ex.Kind);
            }
        }
    }
}
